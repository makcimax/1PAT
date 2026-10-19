#!/usr/bin/env python3
"""Удалённая выгрузка dbo.v8users с MSSQL.

Подключается к серверу теми же способами входа, что Impacket mssqlclient:
пароль аргументом, SQL-логин, Windows/NTLM, NTLM-хеш, Kerberos (пароль,
ccache, AES-ключ). Impacket используется только как TDS-клиент.
"""

from __future__ import annotations

import argparse
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
HEX_BYTES_RE = re.compile(rb"^(?:0x)?[0-9A-Fa-f]+$")
TARGET_RE = re.compile(r"(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)")
# SQL Server 2008/R2 and old compatibility levels reject OFFSET/FETCH.
# The Russian engine says "параметра NEXT в инструкции FETCH", not "FETCH NEXT".
OFFSET_UNSUPPORTED_RE = re.compile(
    r"OFFSET|\bFETCH\b|\bNEXT\b|синтаксис|syntax|недопустим",
    re.IGNORECASE,
)


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
    """Тот же формат, что у Impacket: [[domain/]username[:password]@]host."""
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
    """Вход через login() или kerberosLogin() Impacket. Только аутентификация."""
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
    """Thin wrapper over impacket.tds.MSSQL: connect / login / SELECT only."""

    def __init__(self, options: ConnectOptions, verbose: bool = False):
        self.verbose = verbose
        try:
            from impacket.tds import MSSQL
        except ImportError as exc:
            raise SystemExit(
                "Impacket is required. Install with: pip install impacket"
            ) from exc

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
    """Read v8users. Default is one SELECT. --page-size uses OFFSET, then a full SELECT if the server rejects it."""
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


def fetch_v8users(
    client: QueryClient,
    database: str,
    page_size: int = DEFAULT_PAGE_SIZE,
    verbose: bool = False,
) -> list[dict[str, object]]:
    return list(iter_v8users(client, database, page_size, verbose=verbose))


def export_from_client(
    client: QueryClient,
    only: Sequence[str] | None = None,
    page_size: int = DEFAULT_PAGE_SIZE,
    on_line: Callable[[str], None] | None = None,
    verbose: bool = False,
) -> tuple[list[str], list[str]]:
    """Write rows immediately via on_line. The list is returned only without a callback."""
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
    """Пишет каждую строку сразу, не копит дамп в памяти."""
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


def build_parser(description: str | None = None) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=description
        or (
            "Export dbo.v8users from a remote MSSQL server. "
            "Password is passed as an argument. Authentication matches Impacket mssqlclient."
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


def run_export(
    options: ConnectOptions,
    databases: Sequence[str],
    output: Path | None,
    page_size: int = DEFAULT_PAGE_SIZE,
    transform: Callable[[str], str | None] | None = None,
    verbose: bool = False,
) -> int:
    write, finish = open_line_writer(output)

    def on_line(line: str) -> None:
        if transform is not None:
            line = transform(line)
            if line is None:
                return
        write(line)

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
    if not processed:
        print("No databases with dbo.v8users were found.", file=sys.stderr)
        return 1
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        options = settings_from_args(args)
        return run_export(
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
