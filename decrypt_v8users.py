#!/usr/bin/env python3
"""Расшифровывает поле 0x... в UTF-8 файле с разделителем ';' и заменяет его на

    name:desc:osname:date:hash1:hash2

Остальные поля строки не меняются. Строки, которые расшифровать нельзя, отбрасываются.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import re
import sys
import traceback
from collections.abc import Iterable, Sequence
from datetime import datetime
from pathlib import Path

HEX_FIELD_RE = re.compile(r"^0[xX]([0-9A-Fa-f]+)$")
HASH_PAIR_RE = re.compile(r'\d+,\d+,"(\S+)","(\S+)",\d+,\d+')
DATE_RE = re.compile(r"\d{14}")
DATE_FMT = "%Y%m%d%H%M%S"


def extract_valid_date(text: str) -> str:
    """Первая подстрока YYYYMMDDHHMMSS, которая является реальной датой."""
    for match in DATE_RE.findall(text):
        try:
            datetime.strptime(match, DATE_FMT)
        except ValueError:
            continue
        return match
    return ""


def extract_values_234(text: str) -> tuple[str, str, str]:
    """name, desc, osname — поля 1..3 после split(',')."""
    parts = text.split(",")
    values: list[str] = []
    for index in range(1, 4):
        if index < len(parts):
            values.append(parts[index].strip('" '))
        else:
            values.append("")
    return values[0], values[1], values[2]


def extract_hashes(text: str) -> tuple[str, str] | None:
    """Два Base64-значения из шаблона исходного дампа → lowercase hex."""
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
    """Тот же XOR: первый байт — длина ключа, далее ключ, затем данные."""
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


def encrypt_block(plaintext: bytes, key: bytes) -> bytes:
    """Обратная операция к decrypt_block — только для тестов и примеров."""
    if not key or len(key) > 255:
        raise ValueError("key must be 1..255 bytes")
    out = bytearray([len(key)])
    out.extend(key)
    key_index = 1
    for byte in plaintext:
        if key_index > len(key):
            key_index = 1
        out.append(byte ^ out[key_index])
        key_index += 1
    return bytes(out)


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
    """Replace the first 0xHEX field. None means the line should be dropped."""
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


def iter_processed_lines(
    lines: Iterable[str],
    verbose: bool = False,
) -> tuple[list[str], int, int]:
    changed = 0
    deleted = 0
    results: list[str] = []
    for line_no, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        original = line.rstrip("\r\n")
        result = process_line(original)
        if result is None:
            deleted += 1
            if verbose:
                preview = original[:120].replace("\n", " ")
                print(f"dropped line {line_no}: no decryptable 0x... field ({preview})", file=sys.stderr)
            continue
        if result != original:
            changed += 1
        elif verbose:
            print(f"line {line_no}: kept without DATA change", file=sys.stderr)
        results.append(result)
    return results, changed, deleted


def process_paths(
    input_file: Path,
    output_file: Path | None,
    verbose: bool = False,
) -> tuple[int, int]:
    if verbose:
        size = input_file.stat().st_size if input_file.is_file() else 0
        print(f"reading {input_file} ({size} bytes)", file=sys.stderr)
    try:
        text = input_file.read_text(encoding="utf-8-sig")
    except OSError as exc:
        print(f"Error reading file: {exc}", file=sys.stderr)
        if verbose:
            traceback.print_exc()
        raise SystemExit(1) from exc

    results, changed, deleted = iter_processed_lines(
        text.splitlines(keepends=True),
        verbose=verbose,
    )

    if output_file is not None:
        try:
            output_file.write_text("\n".join(results) + ("\n" if results else ""), encoding="utf-8")
        except OSError as exc:
            print(f"Error writing output file: {exc}", file=sys.stderr)
            if verbose:
                traceback.print_exc()
            raise SystemExit(1) from exc
        print(
            f"Done. Changed lines: {changed}, dropped lines: {deleted}",
            file=sys.stderr,
        )
        print(f"Output: {output_file}", file=sys.stderr)
    else:
        if verbose:
            print(f"writing {len(results)} lines to stdout", file=sys.stderr)
        for result in results:
            sys.stdout.write(result + "\n")

    return changed, deleted


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Decrypts the DATA field (0x...) to "
            "name:desc:osname:date:hash1:hash2. Other fields are kept. "
            "Lines that cannot be decrypted are dropped."
        )
    )
    parser.add_argument(
        "input_file",
        type=Path,
        help="Input v8users table dump in UTF-8",
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
        process_paths(args.input_file, args.output, verbose=args.verbose)
    except SystemExit:
        raise
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        if args.verbose:
            traceback.print_exc()
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
