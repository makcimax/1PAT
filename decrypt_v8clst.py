#!/usr/bin/env python3
"""Decrypt DBMS account passwords from a 1C cluster registry file 1CV8Clst.lst.

The file stores identifiers and AES-128-CBC encrypted passwords of the DBMS
accounts used by the cluster. The key and IV are public platform constants.
"""

from __future__ import annotations

import argparse
import base64
import re
import sys
import traceback
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

try:
    from Crypto.Cipher import AES
except ImportError:  # pragma: no cover
    AES = None  # type: ignore[assignment]


AES_KEY = bytes.fromhex("7D5A39D625A10A476FAD6AB519C4E092")
AES_IV = bytes.fromhex("6D4A7FD2C4A791B48E4296A6B3CF765D")
DBMS_TYPES = frozenset(
    {"MSSQLServer", "PostgreSQL", "IBMDB2", "OracleDatabase"}
)
OUTPUT_HEADER = "infobase;description;dbms;server;database;user;password"


@dataclass(frozen=True)
class InfobaseAccount:
    infobase: str
    description: str
    dbms: str
    server: str
    database: str
    user: str
    password: str
    ciphertext: str


class ParseError(ValueError):
    pass


def require_aes() -> None:
    if AES is None:
        raise SystemExit("Install pycryptodome: pip install pycryptodome")


def b64decode_cyberchef(data: str | bytes) -> bytes:
    if isinstance(data, str):
        data = data.encode("ascii", errors="ignore")
    data = b"".join(data.split())
    data += b"=" * (-len(data) % 4)
    return base64.b64decode(data, validate=False)


def decrypt_blob(input_data: str) -> bytes:
    """AES-128-CBC with the public 1C cluster key and IV."""
    require_aes()
    decoded = b64decode_cyberchef(input_data)
    if not decoded or len(decoded) % 16 != 0:
        raise ValueError("ciphertext is not a multiple of the AES block size")
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return cipher.decrypt(decoded)


def extract_password(plaintext: bytes) -> str | None:
    """Password is the first 1C-quoted field: <prefix>,"<password>"."""
    text = plaintext.decode("utf-8", errors="replace")
    marker = text.find(',"')
    if marker < 0:
        return None
    index = marker + 2
    out: list[str] = []
    while index < len(text):
        char = text[index]
        if char == '"':
            if index + 1 < len(text) and text[index + 1] == '"':
                out.append('"')
                index += 2
                continue
            return "".join(out)
        out.append(char)
        index += 1
    return None


def decrypt_password(ciphertext: str) -> str | None:
    if not ciphertext.strip():
        return ""
    try:
        plaintext = decrypt_blob(ciphertext)
    except (ValueError, OSError):
        return None
    password = extract_password(plaintext)
    if password is not None:
        return password
    text = plaintext.decode("utf-8", errors="replace").strip()
    return text or None


def _skip_ws(text: str, index: int) -> int:
    while index < len(text) and text[index] in " \t\r\n":
        index += 1
    return index


def parse_quoted(text: str, index: int) -> tuple[str, int]:
    if index >= len(text) or text[index] != '"':
        raise ParseError("expected quoted string")
    index += 1
    out: list[str] = []
    while index < len(text):
        char = text[index]
        if char == '"':
            if index + 1 < len(text) and text[index + 1] == '"':
                out.append('"')
                index += 2
                continue
            return "".join(out), index + 1
        out.append(char)
        index += 1
    raise ParseError("unterminated quoted string")


def parse_atom(text: str, index: int) -> tuple[str, int]:
    start = index
    while index < len(text) and text[index] not in ",}":
        index += 1
    return text[start:index].strip(), index


def parse_list(text: str, index: int) -> tuple[list[object], int]:
    if index >= len(text) or text[index] != "{":
        raise ParseError("expected '{'")
    index += 1
    items: list[object] = []
    while True:
        index = _skip_ws(text, index)
        if index >= len(text):
            raise ParseError("unterminated list")
        if text[index] == "}":
            return items, index + 1
        if text[index] == ",":
            items.append("")
            index += 1
            continue
        value, index = parse_value(text, index)
        items.append(value)
        index = _skip_ws(text, index)
        if index < len(text) and text[index] == ",":
            index += 1
            continue
        if index < len(text) and text[index] == "}":
            return items, index + 1
        raise ParseError("expected ',' or '}' in list")


def parse_value(text: str, index: int) -> tuple[object, int]:
    index = _skip_ws(text, index)
    if index >= len(text):
        raise ParseError("unexpected end of input")
    if text[index] == "{":
        return parse_list(text, index)
    if text[index] == '"':
        return parse_quoted(text, index)
    return parse_atom(text, index)


def parse_cluster_file(text: str) -> object:
    text = text.lstrip("\ufeff")
    value, _end = parse_value(text, 0)
    return value


def _as_str(value: object) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return ""
    return str(value)


def _field(node: list[object], index: int) -> str:
    if 0 <= index < len(node):
        return _as_str(node[index])
    return ""


def iter_infobase_nodes(node: object) -> list[list[object]]:
    found: list[list[object]] = []

    def walk(current: object) -> None:
        if not isinstance(current, list):
            return
        for item in current:
            if isinstance(item, str) and item in DBMS_TYPES:
                found.append(current)
                break
        for item in current:
            walk(item)

    walk(node)
    return found


def account_from_node(node: list[object]) -> InfobaseAccount | None:
    dbms_idx = next(
        (
            index
            for index, item in enumerate(node)
            if isinstance(item, str) and item in DBMS_TYPES
        ),
        None,
    )
    if dbms_idx is None or dbms_idx < 3:
        return None
    ciphertext = _field(node, dbms_idx + 4)
    password = decrypt_password(ciphertext)
    if password is None:
        password = ""
    return InfobaseAccount(
        infobase=_field(node, dbms_idx - 2),
        description=_field(node, dbms_idx - 1),
        dbms=_field(node, dbms_idx),
        server=_field(node, dbms_idx + 1),
        database=_field(node, dbms_idx + 2),
        user=_field(node, dbms_idx + 3),
        password=password,
        ciphertext=ciphertext,
    )


INFOBASE_RE = re.compile(
    r'\{[0-9a-fA-F-]{36},'
    r'"((?:[^"]|"")*)",'
    r'"((?:[^"]|"")*)",'
    r'"(MSSQLServer|PostgreSQL|IBMDB2|OracleDatabase)",'
    r'"((?:[^"]|"")*)",'
    r'"((?:[^"]|"")*)",'
    r'"((?:[^"]|"")*)",'
    r'"((?:[^"]|"")*)"',
)


def unescape_1c(value: str) -> str:
    return value.replace('""', '"')


def accounts_from_regex(text: str) -> list[InfobaseAccount]:
    accounts: list[InfobaseAccount] = []
    for match in INFOBASE_RE.finditer(text):
        ciphertext = unescape_1c(match.group(7))
        password = decrypt_password(ciphertext)
        accounts.append(
            InfobaseAccount(
                infobase=unescape_1c(match.group(1)),
                description=unescape_1c(match.group(2)),
                dbms=match.group(3),
                server=unescape_1c(match.group(4)),
                database=unescape_1c(match.group(5)),
                user=unescape_1c(match.group(6)),
                password="" if password is None else password,
                ciphertext=ciphertext,
            )
        )
    return accounts


def extract_accounts(text: str, verbose: bool = False) -> list[InfobaseAccount]:
    try:
        tree = parse_cluster_file(text)
        accounts = [
            account
            for account in (account_from_node(node) for node in iter_infobase_nodes(tree))
            if account is not None
        ]
        if accounts:
            return accounts
        if verbose:
            print("parser found no infobase records, trying regex fallback", file=sys.stderr)
    except ParseError as exc:
        if verbose:
            print(f"cluster file parse failed: {exc}; trying regex fallback", file=sys.stderr)
    return accounts_from_regex(text)


def looks_like_cluster_text(text: str) -> bool:
    return "{" in text and any(dbms in text for dbms in DBMS_TYPES)


def looks_like_ciphertext(text: str) -> bool:
    compact = "".join(text.split())
    if len(compact) < 16:
        return False
    return re.fullmatch(r"[A-Za-z0-9+/_-]+=*", compact) is not None


def format_account(account: InfobaseAccount) -> str:
    fields = (
        account.infobase,
        account.description,
        account.dbms,
        account.server,
        account.database,
        account.user,
        account.password,
    )
    return ";".join(field.replace(";", ",") for field in fields)


def write_lines(lines: list[str], output: Path | None) -> None:
    payload = "\n".join(lines) + ("\n" if lines else "")
    if output is None:
        sys.stdout.write(payload)
        return
    output.write_text(payload, encoding="utf-8")
    print(f"Wrote lines: {len(lines)}", file=sys.stderr)
    print(f"Output: {output}", file=sys.stderr)


def process_ciphertext(ciphertext: str, output: Path | None, verbose: bool) -> int:
    try:
        plaintext = decrypt_blob(ciphertext)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        if verbose:
            traceback.print_exc()
        return 1
    password = extract_password(plaintext)
    decoded = plaintext.decode("utf-8", errors="replace")
    if verbose:
        print(f"plaintext: {decoded!r}", file=sys.stderr)
    write_lines([password if password is not None else decoded], output)
    return 0


def process_cluster_text(text: str, output: Path | None, verbose: bool) -> int:
    accounts = extract_accounts(text, verbose=verbose)
    if verbose:
        print(f"found infobase records: {len(accounts)}", file=sys.stderr)
        for account in accounts:
            preview = account.ciphertext[:24] + ("..." if len(account.ciphertext) > 24 else "")
            print(
                f"{account.infobase}: {account.user}@{account.server}/{account.database} "
                f"cipher={preview!r} password_len={len(account.password)}",
                file=sys.stderr,
            )
    lines = [OUTPUT_HEADER, *[format_account(account) for account in accounts]]
    write_lines(lines, output)
    return 0


def read_input(source: str) -> tuple[str, str]:
    """Return (kind, payload) where kind is 'file', 'cipher', or 'text'."""
    if source == "-":
        payload = sys.stdin.read()
        if looks_like_cluster_text(payload):
            return "file", payload
        return "cipher", payload.strip()
    path = Path(source)
    if path.is_file():
        return "file", path.read_text(encoding="utf-8-sig")
    if looks_like_ciphertext(source):
        return "cipher", source.strip()
    raise SystemExit(f"Input file not found: {source}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Decrypt DBMS account passwords from a 1CV8Clst.lst cluster "
            "registry file. The AES-128-CBC key and IV are public 1C "
            "platform constants."
        )
    )
    parser.add_argument(
        "input",
        help="1CV8Clst.lst file, a single Base64 ciphertext, or '-' for stdin",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Output file. Defaults to stdout",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print extra diagnostic information",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        kind, payload = read_input(args.input)
        if kind == "cipher":
            return process_ciphertext(payload, args.output, args.verbose)
        if not looks_like_cluster_text(payload) and looks_like_ciphertext(payload.strip()):
            return process_ciphertext(payload.strip(), args.output, args.verbose)
        return process_cluster_text(payload, args.output, args.verbose)
    except SystemExit:
        raise
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        if args.verbose:
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
