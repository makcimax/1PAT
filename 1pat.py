#!/usr/bin/env python3
"""1C Password Audit Tool (1PAT).

Reads a semicolon dump and a Hashcat potfile, then builds a DPAT-style HTML report.
"""

from __future__ import annotations

import argparse
import hashlib
import html as htmllib
import os
import re
import sqlite3
import sys
import time
import traceback
import webbrowser
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from shutil import copyfile

DEFAULT_REPORT_NAME = "_1CPasswordAuditReport.html"
DEFAULT_REPORT_DIR = "1PAT Report"
DEFAULT_DB_NAME = "pass_audit.db"
SHA1_LEN = 40
NTLM_LEN = 32
MAX_CASE_LETTERS = 8
HISTORY_RE = re.compile(r"(?i)(.*\\*.*)_history([0-9]+)$")
HEX_ONLY_RE = re.compile(r"[^0-9a-fA-F]")
SAFE_FILENAME_RE = re.compile(r'[\\/:*?"<>|\x00-\x1f]+')
GROUP_COL_RE = re.compile(r"[^\w.\- ]+", re.UNICODE)

GROUP_MATCH_SQL = """
    JOIN group_membership g
      ON g.group_name = ?
     AND (
            g.username_full = h.username_full
         OR g.username_full = h.username_long_full
         OR g.username_full = h.username
         OR g.username_full = h.username_long
     )
"""


@dataclass(frozen=True)
class Labels:
    lang: str
    count: str
    description: str
    more_info: str
    username: str
    password: str
    password_length: str
    sha1_normal: str
    sha1_upper: str
    details: str
    password_hashes: str
    passwords_cracked: str
    percent_cracked: str
    unique_hashes: str
    unique_cracked: str
    percent_unique: str
    members_of: str
    length_stats: str
    top_stats: str
    reuse_stats: str
    db_stats: str
    users_sharing: str
    users_sharing_this: str
    share_count: str
    users_with_length: str
    too_many: str
    database_name: str
    total_users: str
    cracked_count: str
    cracked_pct: str
    statistics: str
    no_records: str
    report_title: str
    reading_v8users: str
    admin_status: str
    admin_accounts: str
    admin_yes: str
    admin_no: str
    processed_lines: str
    reading_crack: str
    found_matches: str
    trying_case: str
    cracked_case: str
    generating_main: str
    generating_db: str
    report_written: str
    open_prompt: str
    yes_no_hint: str
    empty_password: str
    empty_passwords: str
    users_with_empty: str
    login_status: str
    login_yes: str
    login_no: str
    login_disabled: str

    @property
    def summary_headers(self) -> tuple[str, str, str]:
        return (self.count, self.description, self.more_info)

    @property
    def all_hash_headers(self) -> list[str]:
        return [
            self.username,
            self.password,
            self.password_length,
            self.sha1_normal,
            self.sha1_upper,
            self.admin_status,
            self.login_status,
        ]

    def details_link(self, filename: str) -> str:
        return f'<a href="{htmllib.escape(filename, quote=True)}">{self.details}</a>'

    def is_secret_header(self, header: str) -> bool:
        if not header or header == self.password_length:
            return False
        if header == self.password:
            return True
        if header in (self.sha1_normal, self.sha1_upper):
            return True
        if "History" in header or "истори" in header.lower():
            return True
        return False


LABELS = {
    "en": Labels(
        lang="en",
        count="Count",
        description="Description",
        more_info="More Info",
        username="Username",
        password="Password",
        password_length="Password Length",
        sha1_normal="SHA1 Hash (Normal)",
        sha1_upper="SHA1 Hash (UPPERCASE)",
        details="Details",
        password_hashes="Password Hashes",
        passwords_cracked="Passwords Discovered Through Cracking",
        percent_cracked="Percent of Passwords Cracked",
        unique_hashes="Unique Password Hashes",
        unique_cracked="Unique Passwords Discovered Through Cracking",
        percent_unique="Percent of Unique Passwords Cracked",
        members_of='Members of "{group}" group',
        length_stats="Password Length Stats",
        top_stats="Top Password Use Stats",
        reuse_stats="Password Reuse Stats",
        db_stats="Statistics for each database",
        users_sharing="Users Sharing hash:password of {hashpass}",
        users_sharing_this="Users Sharing this Hash",
        share_count="Share Count",
        users_with_length="Users with a password length of {length}",
        too_many="Too Many to List",
        database_name="Database Name",
        total_users="Total Users",
        cracked_count="Passwords Cracked",
        cracked_pct="Cracked %",
        statistics="Statistics",
        no_records="No records found for database: {db}",
        report_title="1PAT Report",
        reading_v8users="Reading v8users file: {path}",
        admin_status="AdminStatus",
        admin_accounts="Admin Accounts",
        admin_yes="True",
        admin_no="False",
        processed_lines="Processed {lines} lines, inserted {inserted} records",
        reading_crack="Reading crack file: {path}",
        found_matches="Found {count} password matches in crack file",
        trying_case="Attempting to crack uppercase hashes using case variations...",
        cracked_case="Cracked {count} uppercase hashes using case variations",
        generating_main="\nGenerating main report...",
        generating_db="Generating statistics for each database...",
        report_written='The Report has been written to the "{name}" file in the "{directory}" directory',
        open_prompt="Would you like to open the report now? [Y/n]",
        yes_no_hint="Please respond with y or n",
        empty_password="(empty password)",
        empty_passwords="Empty passwords discovered through cracking",
        users_with_empty="Users with an empty password",
        login_status="Login",
        login_yes="Enabled",
        login_no="Disabled",
        login_disabled="Users with login disabled",
    ),
    "ru": Labels(
        lang="ru",
        count="Количество",
        description="Описание",
        more_info="Подробнее",
        username="Учётная запись",
        password="Пароль",
        password_length="Длина пароля",
        sha1_normal="Хеш SHA1 (обычный)",
        sha1_upper="Хеш SHA1 (ВЕРХНИЙ РЕГИСТР)",
        details="Подробнее",
        password_hashes="Хеши паролей",
        passwords_cracked="Подобранные пароли",
        percent_cracked="Доля подобранных паролей",
        unique_hashes="Уникальные хеши паролей",
        unique_cracked="Уникальные подобранные пароли",
        percent_unique="Доля уникальных подобранных паролей",
        members_of="Участники группы «{group}»",
        length_stats="Статистика по длине пароля",
        top_stats="Самые частые пароли",
        reuse_stats="Повторное использование паролей",
        db_stats="Статистика по каждой базе",
        users_sharing="Пользователи с общим хешем:паролем {hashpass}",
        users_sharing_this="Кто ещё с этим хешем",
        share_count="Сколько учёток",
        users_with_length="Пользователи с паролем длины {length}",
        too_many="Слишком много, чтобы перечислить",
        database_name="База",
        total_users="Всего учёток",
        cracked_count="Паролей подобрано",
        cracked_pct="Доля",
        statistics="Статистика",
        no_records="Нет записей для базы: {db}",
        report_title="Отчёт 1PAT",
        reading_v8users="Читаю файл v8users: {path}",
        admin_status="Админ",
        admin_accounts="Администраторы",
        admin_yes="Да",
        admin_no="Нет",
        processed_lines="Обработано строк: {lines}, записано: {inserted}",
        reading_crack="Читаю potfile: {path}",
        found_matches="Совпадений паролей в potfile: {count}",
        trying_case="Подбираю регистр для хешей в верхнем регистре...",
        cracked_case="Подобрано по регистру: {count}",
        generating_main="\nСобираю основной отчёт...",
        generating_db="Собираю статистику по базам...",
        report_written='Отчёт записан в файл «{name}» в каталоге «{directory}»',
        open_prompt="Открыть отчёт сейчас? [Y/n]",
        yes_no_hint="Ответьте y или n",
        empty_password="(пустой пароль)",
        empty_passwords="Подобранные пустые пароли",
        users_with_empty="Пользователи с пустым паролем",
        login_status="Вход",
        login_yes="Включён",
        login_no="Выключен",
        login_disabled="Пользователи с выключенным входом",
    ),
}


def get_labels(lang: str) -> Labels:
    return LABELS.get(lang, LABELS["en"])


@dataclass
class Settings:
    v8users_file: Path
    crack_file: Path
    output_file: str = DEFAULT_REPORT_NAME
    report_directory: Path = Path(DEFAULT_REPORT_DIR)
    write_db: bool = False
    sanitize_output: bool = False
    group_lists: list[tuple[str, Path]] = field(default_factory=list)
    db_path: Path = Path(DEFAULT_DB_NAME)
    lang: str = "ru"
    open_report: bool = False
    verbose: bool = False

    @property
    def labels(self) -> Labels:
        return get_labels(self.lang)


@dataclass(frozen=True)
class MarkedCell:
    text: str
    css_class: str = ""

    def __str__(self) -> str:
        return self.text


def display_password(value: str | None, labels: Labels) -> object:
    if value is None:
        return ""
    if value == "":
        return MarkedCell(labels.empty_password, "empty-password")
    return value


def password_key(value: object) -> str | None:
    if isinstance(value, MarkedCell) and value.css_class == "empty-password":
        return ""
    if value is None or value == "":
        return None
    return str(value)


def sanitize_value(pass_or_hash: str, enabled: bool) -> str:
    """Та же маска, что в исходном скрипте: края видны, середина звёздами."""
    if not enabled or not pass_or_hash:
        return pass_or_hash
    length = len(pass_or_hash)
    if length in (SHA1_LEN, NTLM_LEN):
        return pass_or_hash[0:4] + ("*" * (length - 8)) + pass_or_hash[length - 5 : length - 1]
    if length > 2:
        return pass_or_hash[0] + ("*" * (length - 2)) + pass_or_hash[length - 1]
    return pass_or_hash


def safe_filename(name: str) -> str:
    cleaned = SAFE_FILENAME_RE.sub("_", name).strip(" .")
    return cleaned or "unnamed"


def group_column_name(name: str) -> str:
    cleaned = GROUP_COL_RE.sub("_", name).strip()
    return cleaned or "group"


def normalize_hex(value: str) -> str:
    return HEX_ONLY_RE.sub("", value).lower()


def read_text_autodetect(path: Path) -> str:
    data = path.read_bytes()
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16")
    if data.startswith(b"\xef\xbb\xbf"):
        return data.decode("utf-8-sig")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("cp1251")


def parse_powerview_members(text: str) -> list[str]:
    users: list[str] = []
    user_domain = ""
    for raw in text.splitlines():
        line = raw.strip()
        if "MemberDomain" in line and ":" in line:
            user_domain = line.split(":", 1)[1].strip()
        elif "MemberName" in line and ":" in line:
            user_name = line.split(":", 1)[1].strip()
            users.append(f"{user_domain}\\{user_name}")
    return users


def load_group_users(path: Path) -> list[str]:
    text = read_text_autodetect(path)
    if "MemberDomain" in text and "MemberName" in text:
        users = parse_powerview_members(text)
        if users:
            return users
    return [line.rstrip("\n") for line in text.splitlines() if line.strip()]


def all_casings(input_string: str) -> Iterator[str]:
    """Все варианты регистра. Для не-букв ветка одна."""
    if not input_string:
        yield ""
        return
    first, rest = input_string[:1], input_string[1:]
    if first.lower() == first.upper():
        for sub in all_casings(rest):
            yield first + sub
        return
    for sub in all_casings(rest):
        yield first.lower() + sub
        yield first.upper() + sub


def limited_casings(password: str) -> Iterator[str]:
    letters = sum(1 for ch in password if ch.lower() != ch.upper())
    seen: set[str] = set()
    cheap = (password, password.lower(), password.upper(), password.capitalize(), password.swapcase())
    for item in cheap:
        if item not in seen:
            seen.add(item)
            yield item
    if letters <= MAX_CASE_LETTERS:
        for item in all_casings(password):
            if item not in seen:
                seen.add(item)
                yield item


class HtmlBuilder:
    def __init__(self, report_directory: Path, sanitize_output: bool, css_source: Path, labels: Labels):
        self.body_str = ""
        self.report_directory = report_directory
        self.sanitize_output = sanitize_output
        self.css_source = css_source
        self.labels = labels

    def build_html_body_string(self, chunk: str) -> None:
        self.body_str += chunk + "</br>\n"

    def get_html(self) -> str:
        return (
            "<!DOCTYPE html>\n"
            f'<html lang="{self.labels.lang}">\n'
            "<head>\n"
            "<meta charset='utf-8'>\n"
            f"<title>{htmllib.escape(self.labels.report_title)}</title>\n"
            "<link rel='stylesheet' href='report.css'>\n"
            "</head>\n"
            "<body>\n"
            f"{self.body_str}"
            "</body>\n"
            "</html>\n"
        )

    def add_table_to_html(
        self,
        rows: Iterable[Sequence[object]],
        headers: Sequence[str | None] | None = None,
        col_to_not_escape: int | None = None,
    ) -> None:
        headers = list(headers or [])
        html = ['<table border="1">\n<tr>']
        for header in headers:
            html.append(f"<th>{header if header is not None else ''}</th>")
        html.append("</tr>\n")

        for line in rows:
            row_class = ""
            if any(isinstance(column, MarkedCell) and column.css_class == "empty-password" for column in line):
                row_class = ' class="empty-password-row"'
            html.append(f"<tr{row_class}>")
            for col_num, column in enumerate(line):
                if column is None:
                    html.append("<td></td>")
                    continue
                if isinstance(column, MarkedCell):
                    text = column.text if col_num == col_to_not_escape else htmllib.escape(column.text)
                    css = f' class="{htmllib.escape(column.css_class, quote=True)}"' if column.css_class else ""
                    html.append(f"<td{css}>{text}</td>")
                    continue
                header = headers[col_num] if col_num < len(headers) else ""
                col_data: object = column
                header_text = header or ""
                if self.labels.is_secret_header(header_text):
                    col_data = sanitize_value(str(column), self.sanitize_output)
                if col_num != col_to_not_escape:
                    col_data = htmllib.escape(str(col_data))
                html.append(f"<td>{col_data}</td>")
            html.append("</tr>\n")
        html.append("</table>")
        self.build_html_body_string("".join(html))

    def write_html_report(self, filename: str) -> str:
        self.report_directory.mkdir(parents=True, exist_ok=True)
        css_dest = self.report_directory / "report.css"
        if self.css_source.is_file():
            copyfile(self.css_source, css_dest)
        else:
            css_dest.write_text(FALLBACK_CSS, encoding="utf-8")
        (self.report_directory / filename).write_text(self.get_html(), encoding="utf-8")
        return filename


FALLBACK_CSS = Path(__file__).with_name("report.css").read_text(encoding="utf-8") if Path(__file__).with_name("report.css").is_file() else """
body { font-family: Arial, sans-serif; margin: 20px; }
table { border-collapse: collapse; width: 100%; margin: 10px 0; }
th { background-color: #4CAF50; color: white; padding: 8px; text-align: left; }
td { padding: 8px; border: 1px solid #ddd; }
tr:nth-child(even) { background-color: #f2f2f2; }
a { color: #0066cc; text-decoration: none; }
a:hover { text-decoration: underline; }
td.empty-password { background-color: #c62828; color: #fff; font-weight: bold; text-align: center; }
tr.empty-password-row { outline: 2px solid #c62828; }
"""


def connect_db(settings: Settings) -> sqlite3.Connection:
    if settings.write_db:
        if settings.db_path.exists():
            settings.db_path.unlink()
        conn = sqlite3.connect(settings.db_path)
    else:
        conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE hash_infos (
            database_name TEXT,
            username_full TEXT COLLATE NOCASE,
            username TEXT COLLATE NOCASE,
            username_long TEXT COLLATE NOCASE,
            username_long_full TEXT COLLATE NOCASE,
            sha1_hash_normal TEXT,
            sha1_hash_uppercase TEXT,
            password TEXT,
            timestamp TEXT,
            history_index INTEGER,
            history_base_username TEXT,
            admin_status TEXT,
            login_enabled TEXT
        );
        CREATE INDEX index_sha1_hash_normal ON hash_infos (sha1_hash_normal);
        CREATE INDEX index_sha1_hash_uppercase ON hash_infos (sha1_hash_uppercase);
        CREATE INDEX username ON hash_infos (username);
        CREATE INDEX idx_password ON hash_infos (password);
        CREATE INDEX idx_database ON hash_infos (database_name);
        CREATE INDEX idx_admin ON hash_infos (admin_status);
        CREATE INDEX idx_login ON hash_infos (login_enabled);
        CREATE TABLE group_membership (
            group_name TEXT NOT NULL,
            username_full TEXT NOT NULL
        );
        CREATE INDEX idx_gm_group ON group_membership (group_name);
        CREATE INDEX idx_gm_user ON group_membership (username_full);
        """
    )


def parse_admin_status(vals: Sequence[str]) -> str:
    """Поле 9 (предпоследнее в типичной строке v8users): 1 = админ, иначе нет."""
    if len(vals) > 9 and vals[9].strip() == "1":
        return "True"
    return "False"


def format_admin(status: str, labels: Labels) -> str:
    return labels.admin_yes if status == "True" else labels.admin_no


def _truthy_flag(value: str) -> bool | None:
    text = value.strip().lower()
    if text in ("1", "true", "yes", "да", "0x01"):
        return True
    if text in ("0", "false", "no", "нет", "0x00"):
        return False
    if text.lstrip("-").isdigit():
        return int(text) != 0
    return None


def parse_login_enabled(vals: Sequence[str]) -> str:
    """Вход включён, если EAuth (поле 8) ≠ 0 или OSName (поле 3) заполнен.

    Отдельного бита «заблокирован» в v8users нет до 8.3.28. Если в строке
    есть 12-е поле LoginEnabled из sql/export_v8users.sql — берём его.
    """
    if len(vals) > 11:
        extra = _truthy_flag(vals[11])
        if extra is not None:
            return "True" if extra else "False"

    eauth = _truthy_flag(vals[8]) if len(vals) > 8 else None
    if eauth:
        return "True"

    osname = vals[3].strip() if len(vals) > 3 else ""
    if osname and osname.upper() not in ("NULL", "NONE"):
        return "True"
    return "False"


def format_login(status: str, labels: Labels) -> str:
    return labels.login_yes if status == "True" else labels.login_no


def import_v8users(conn: sqlite3.Connection, settings: Settings) -> tuple[int, int]:
    text = read_text_autodetect(settings.v8users_file)
    line_count = 0
    inserted = 0
    skipped_short = 0
    skipped_hashes = 0
    rows: list[tuple[object, ...]] = []
    for raw in text.splitlines():
        line_count += 1
        vals = raw.rstrip("\n").split(";")
        if len(vals) < 10:
            skipped_short += 1
            if settings.verbose:
                print(
                    f"skipping short line {line_count}: {len(vals)} fields",
                    file=sys.stderr,
                )
            continue

        database_name = vals[0]
        username_short = vals[1]
        username_long = vals[2]
        timestamp = vals[4]
        hash_parts = vals[7].split(":")
        sha1_hash_normal = normalize_hex(hash_parts[-2] if len(hash_parts) >= 2 else "")
        sha1_hash_uppercase = normalize_hex(hash_parts[-1] if hash_parts else "")

        # Первый столбец отчёта: база + краткое имя (поля 1 и 2 дампа).
        username_full_with_db = f"{database_name}\\{username_short}"
        username_long_full = f"{database_name}\\{username_long}"
        history_base_username = username_full_with_db
        history_index = -1
        history_match = HISTORY_RE.search(username_full_with_db) or HISTORY_RE.search(username_long_full)
        if history_match:
            history_base_username = history_match.group(1)
            history_index = int(history_match.group(2))

        if not (sha1_hash_normal or sha1_hash_uppercase):
            skipped_hashes += 1
            if settings.verbose:
                print(f"skipping line {line_count}: missing SHA1 hashes", file=sys.stderr)
            continue

        rows.append(
            (
                database_name,
                username_full_with_db,
                username_short,
                username_long,
                username_long_full,
                sha1_hash_normal,
                sha1_hash_uppercase,
                timestamp,
                history_index,
                history_base_username,
                parse_admin_status(vals),
                parse_login_enabled(vals),
            )
        )
        inserted += 1

    conn.executemany(
        """
        INSERT INTO hash_infos (
            database_name, username_full, username, username_long, username_long_full,
            sha1_hash_normal, sha1_hash_uppercase, timestamp, history_index,
            history_base_username, admin_status, login_enabled
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    if settings.verbose:
        print(
            f"v8users skipped: short={skipped_short}, missing hashes={skipped_hashes}",
            file=sys.stderr,
        )
    return line_count, inserted


def import_groups(conn: sqlite3.Connection, settings: Settings) -> None:
    for group_name, group_path in settings.group_lists:
        users = load_group_users(group_path)
        conn.executemany(
            "INSERT INTO group_membership (group_name, username_full) VALUES (?, ?)",
            [(group_name, user) for user in users],
        )


def import_potfile(conn: sqlite3.Connection, settings: Settings) -> tuple[int, list[str]]:
    text = read_text_autodetect(settings.crack_file)
    crack_count = 0
    skipped = 0
    pot_passwords: list[str] = []
    for raw in text.splitlines():
        line = raw.rstrip("\r\n")
        if not line.strip():
            continue
        colon_index = line.find(":")
        if colon_index == -1:
            skipped += 1
            if settings.verbose:
                print("skipping potfile line without ':'", file=sys.stderr)
            continue
        hash_val = normalize_hex(line[:colon_index])
        password = line[colon_index + 1 :]
        if len(hash_val) != SHA1_LEN:
            skipped += 1
            if settings.verbose:
                print(
                    f"skipping potfile line: hash length {len(hash_val)} != {SHA1_LEN}",
                    file=sys.stderr,
                )
            continue
        pot_passwords.append(password)
        cursor = conn.execute(
            "UPDATE hash_infos SET password = ? WHERE sha1_hash_normal = ? AND password IS NULL",
            (password, hash_val),
        )
        crack_count += cursor.rowcount
        cursor = conn.execute(
            "UPDATE hash_infos SET password = ? WHERE sha1_hash_uppercase = ? AND password IS NULL",
            (password, hash_val),
        )
        crack_count += cursor.rowcount
    if settings.verbose:
        print(f"potfile skipped lines: {skipped}", file=sys.stderr)
    return crack_count, pot_passwords


def crack_case_variations(conn: sqlite3.Connection, extra_passwords: Sequence[str] | None = None) -> int:
    """Подбирает регистр известных паролей к ещё не раскрытым SHA1."""
    known = {
        row[0]
        for row in conn.execute(
            "SELECT DISTINCT password FROM hash_infos WHERE password IS NOT NULL AND password != ''"
        )
    }
    if extra_passwords:
        known.update(pwd for pwd in extra_passwords if pwd)
    if not known:
        return 0

    unmatched = conn.execute(
        """
        SELECT DISTINCT sha1_hash_normal, sha1_hash_uppercase
        FROM hash_infos
        WHERE password IS NULL
          AND (sha1_hash_normal != '' OR sha1_hash_uppercase != '')
        """
    ).fetchall()
    if not unmatched:
        return 0

    needed: dict[str, str] = {}
    for normal, upper in unmatched:
        if normal:
            needed.setdefault(normal, "normal")
        if upper:
            needed.setdefault(upper, "upper")

    cracked = 0
    for password in known:
        for guess in limited_casings(password):
            digest = hashlib.sha1(guess.encode("utf-8")).hexdigest()
            column = needed.pop(digest, None)
            if column is None:
                continue
            if column == "normal":
                cursor = conn.execute(
                    "UPDATE hash_infos SET password = ? WHERE sha1_hash_normal = ? AND password IS NULL",
                    (guess, digest),
                )
            else:
                cursor = conn.execute(
                    "UPDATE hash_infos SET password = ? WHERE sha1_hash_uppercase = ? AND password IS NULL",
                    (guess, digest),
                )
            cracked += cursor.rowcount
            if not needed:
                return cracked
    return cracked


def current_accounts(conn: sqlite3.Connection, extra_where: str = "", params: Sequence[object] = ()) -> list[sqlite3.Row]:
    sql = f"""
        SELECT username_full, sha1_hash_normal, sha1_hash_uppercase, password,
               database_name, admin_status, login_enabled
        FROM hash_infos
        WHERE history_index = -1 {extra_where}
    """
    return list(conn.execute(sql, params))


def rows_to_hash_list(
    records: Iterable[sqlite3.Row], labels: Labels
) -> list[tuple[str, object, object, str, str, str, str]]:
    result: list[tuple[str, object, object, str, str, str, str]] = []
    for record in records:
        raw = record["password"]
        # Length only for cracked non-empty passwords. Uncracked and empty stay blank.
        length: object = len(raw) if raw else ""
        result.append(
            (
                record["username_full"],
                display_password(raw, labels),
                length,
                record["sha1_hash_normal"] or "",
                record["sha1_hash_uppercase"] or "",
                format_admin(record["admin_status"] or "False", labels),
                format_login(record["login_enabled"] or "False", labels),
            )
        )
    result.sort(
        key=lambda item: (
            password_key(item[1]) is not None,
            item[2] if isinstance(item[2], int) else -1,
        ),
        reverse=True,
    )
    return result


def cracked_count(hash_list: Sequence[Sequence[object]]) -> int:
    return sum(1 for record in hash_list if password_key(record[1]) is not None)


def unique_cracked(hash_list: Sequence[Sequence[object]]) -> int:
    return len({password_key(record[1]) for record in hash_list if password_key(record[1]) is not None})


def unique_hash_count(conn: sqlite3.Connection, extra_where: str = "", params: Sequence[object] = ()) -> int:
    normal = conn.execute(
        f'SELECT COUNT(DISTINCT sha1_hash_normal) FROM hash_infos WHERE sha1_hash_normal != "" {extra_where}',
        params,
    ).fetchone()[0] or 0
    upper = conn.execute(
        f'SELECT COUNT(DISTINCT sha1_hash_uppercase) FROM hash_infos WHERE sha1_hash_uppercase != "" {extra_where}',
        params,
    ).fetchone()[0] or 0
    return int(normal) + int(upper)


def top_passwords(
    hash_list: Sequence[Sequence[object]], labels: Labels, limit: int = 20
) -> list[tuple[object, int]]:
    counts: dict[str, int] = {}
    for record in hash_list:
        key = password_key(record[1])
        if key is None:
            continue
        counts[key] = counts.get(key, 0) + 1
    ranked = sorted(counts.items(), key=lambda item: item[1], reverse=True)[:limit]
    return [(display_password(key, labels), count) for key, count in ranked]


def append_admin_summary(
    summary: list[tuple[object, object, object]],
    hash_list: Sequence[Sequence[object]],
    settings: Settings,
    prefix: str = "",
) -> None:
    labels = settings.labels
    admins = [row for row in hash_list if row[5] == labels.admin_yes]
    if not admins:
        return
    page = new_builder(settings)
    page.add_table_to_html(admins, labels.all_hash_headers)
    filename = page.write_html_report(f"{prefix}admin_accounts.html")
    summary.append((len(admins), labels.admin_accounts, labels.details_link(filename)))


def append_empty_password_summary(
    summary: list[tuple[object, object, object]],
    hash_list: Sequence[Sequence[object]],
    settings: Settings,
    prefix: str = "",
) -> None:
    empty_users = [(row[0],) for row in hash_list if password_key(row[1]) == ""]
    if not empty_users:
        return
    page = new_builder(settings)
    page.add_table_to_html(empty_users, [settings.labels.users_with_empty])
    filename = page.write_html_report(f"{prefix}empty_passwords.html")
    summary.append(
        (len(empty_users), settings.labels.empty_passwords, settings.labels.details_link(filename))
    )


def append_login_disabled_summary(
    summary: list[tuple[object, object, object]],
    hash_list: Sequence[Sequence[object]],
    settings: Settings,
    prefix: str = "",
) -> None:
    labels = settings.labels
    disabled = [row for row in hash_list if row[6] == labels.login_no]
    if not disabled:
        return
    page = new_builder(settings)
    page.add_table_to_html(disabled, labels.all_hash_headers)
    filename = page.write_html_report(f"{prefix}login_disabled.html")
    summary.append((len(disabled), labels.login_disabled, labels.details_link(filename)))


def new_builder(settings: Settings) -> HtmlBuilder:
    return HtmlBuilder(
        report_directory=settings.report_directory,
        sanitize_output=settings.sanitize_output,
        css_source=Path(__file__).with_name("report.css"),
        labels=settings.labels,
    )


def write_reuse_details(
    conn: sqlite3.Connection,
    settings: Settings,
    db_name: str | None,
    prefix: str,
) -> list[tuple[object, ...]]:
    if db_name:
        reuse = conn.execute(
            """
            SELECT sha1_hash_normal, sha1_hash_uppercase, COUNT(*) AS count, password
            FROM hash_infos
            WHERE database_name = ?
              AND (sha1_hash_normal != '' OR sha1_hash_uppercase != '')
            GROUP BY sha1_hash_normal, sha1_hash_uppercase
            ORDER BY count DESC
            LIMIT 20
            """,
            (db_name,),
        ).fetchall()
    else:
        reuse = conn.execute(
            """
            SELECT sha1_hash_normal, sha1_hash_uppercase, COUNT(*) AS count
            FROM hash_infos
            WHERE history_index = -1
              AND (sha1_hash_normal != '' OR sha1_hash_uppercase != '')
            GROUP BY sha1_hash_normal, sha1_hash_uppercase
            ORDER BY count DESC
            LIMIT 20
            """
        ).fetchall()

    rows: list[tuple[object, ...]] = []
    for index, item in enumerate(reuse):
        hash_val = item["sha1_hash_normal"] or item["sha1_hash_uppercase"]
        password = item["password"] if "password" in item.keys() else None
        if password is None:
            found = conn.execute(
                """
                SELECT password FROM hash_infos
                WHERE (sha1_hash_normal = ? OR sha1_hash_uppercase = ?)
                  AND password IS NOT NULL
                LIMIT 1
                """,
                (item["sha1_hash_normal"], item["sha1_hash_uppercase"]),
            ).fetchone()
            password = found["password"] if found else None
        if db_name:
            usernames = conn.execute(
                """
                SELECT username FROM hash_infos
                WHERE database_name = ?
                  AND (sha1_hash_normal = ? OR sha1_hash_uppercase = ?)
                  AND history_index = -1
                """,
                (db_name, hash_val, hash_val),
            ).fetchall()
        else:
            usernames = conn.execute(
                """
                SELECT username FROM hash_infos
                WHERE (sha1_hash_normal = ? OR sha1_hash_uppercase = ?)
                  AND history_index = -1
                """,
                (hash_val, hash_val),
            ).fetchall()
        username_rows = sorted((row[0],) for row in usernames)
        page = new_builder(settings)
        shown = display_password(password, settings.labels)
        hashpass_pw = (
            settings.labels.empty_password
            if password == ""
            else sanitize_value(password or "", settings.sanitize_output)
        )
        hashpass = sanitize_value(hash_val or "", settings.sanitize_output) + ":" + hashpass_pw
        page.add_table_to_html(
            username_rows,
            [settings.labels.users_sharing.format(hashpass=hashpass)],
        )
        filename = page.write_html_report(f"{prefix}{index}_reuse_usernames.html")
        rows.append(
            (
                item["sha1_hash_normal"],
                item["sha1_hash_uppercase"],
                item["count"],
                shown,
                settings.labels.details_link(filename),
            )
        )
    return rows


def generate_db_statistics(conn: sqlite3.Connection, settings: Settings, db_name: str) -> HtmlBuilder:
    db_hb = new_builder(settings)
    records = current_accounts(conn, "AND database_name = ?", (db_name,))
    db_list = rows_to_hash_list(records, settings.labels)
    db_summary: list[tuple[object, object, object]] = []

    labels = settings.labels
    if not db_list:
        db_hb.build_html_body_string(labels.no_records.format(db=db_name))
        return db_hb

    page = new_builder(settings)
    page.add_table_to_html(db_list, labels.all_hash_headers)
    filename = page.write_html_report(f"{safe_filename(db_name)}_all_hashes.html")
    db_total = len(db_list)
    cracked = cracked_count(db_list)
    unique_hashes = unique_hash_count(conn, "AND database_name = ?", (db_name,))
    unique_pass = unique_cracked(db_list)
    percent_cracked = (cracked / float(db_total) * 100) if db_total else 0
    percent_unique = (unique_pass / float(unique_hashes) * 100) if unique_hashes else 0

    db_summary.append((db_total, labels.password_hashes, labels.details_link(filename)))
    append_admin_summary(db_summary, db_list, settings, f"{safe_filename(db_name)}_")
    append_login_disabled_summary(db_summary, db_list, settings, f"{safe_filename(db_name)}_")
    db_summary.append((cracked, labels.passwords_cracked, None))
    db_summary.append((f"{percent_cracked:0.1f}%", labels.percent_cracked, None))
    db_summary.append((unique_hashes, labels.unique_hashes, None))
    db_summary.append((unique_pass, labels.unique_cracked, None))
    db_summary.append((f"{percent_unique:0.1f}%", labels.percent_unique, None))
    append_empty_password_summary(db_summary, db_list, settings, f"{safe_filename(db_name)}_")

    tops = top_passwords(db_list, labels)
    if tops:
        page = new_builder(settings)
        page.add_table_to_html(tops, [labels.password, labels.count])
        filename = page.write_html_report(f"{safe_filename(db_name)}_top_password_stats.html")
        db_summary.append((None, labels.top_stats, labels.details_link(filename)))

    reuse = write_reuse_details(conn, settings, db_name, f"{safe_filename(db_name)}_")
    if reuse:
        page = new_builder(settings)
        page.add_table_to_html(
            reuse,
            [labels.sha1_normal, labels.sha1_upper, labels.count, labels.password, labels.details],
            4,
        )
        filename = page.write_html_report(f"{safe_filename(db_name)}_password_reuse_stats.html")
        db_summary.append((None, labels.reuse_stats, labels.details_link(filename)))

    for group_name, _path in settings.group_lists:
        group_rows = conn.execute(
            f"""
            SELECT h.username_full, h.sha1_hash_normal, h.sha1_hash_uppercase,
                   h.password, h.admin_status, h.login_enabled
            FROM hash_infos h
            {GROUP_MATCH_SQL}
            WHERE h.database_name = ? AND h.history_index = -1
            """,
            (group_name, db_name),
        ).fetchall()
        if not group_rows:
            continue
        db_summary.append((len(group_rows), labels.members_of.format(group=group_name), None))

    db_hb.add_table_to_html(db_summary, labels.summary_headers, 2)
    return db_hb


def generate_reports(conn: sqlite3.Connection, settings: Settings) -> Path:
    labels = settings.labels
    print(LABELS["en"].generating_main, file=sys.stderr)
    summary: list[tuple[object, object, object]] = []
    main_list = rows_to_hash_list(current_accounts(conn), labels)
    num_hashes = len(main_list)

    page = new_builder(settings)
    page.add_table_to_html(main_list, labels.all_hash_headers)
    filename = page.write_html_report("all_hashes.html")
    summary.append((num_hashes, labels.password_hashes, labels.details_link(filename)))
    append_admin_summary(summary, main_list, settings)
    append_login_disabled_summary(summary, main_list, settings)

    num_cracked = cracked_count(main_list)
    percent_cracked = (num_cracked / float(num_hashes) * 100) if num_hashes else 0
    summary.append((num_cracked, labels.passwords_cracked, None))
    summary.append((f"{percent_cracked:0.1f}%", labels.percent_cracked, None))

    unique_hashes = unique_hash_count(conn, "AND history_index = -1")
    unique_pass = unique_cracked(main_list)
    percent_unique = (unique_pass / float(unique_hashes) * 100) if unique_hashes else 0
    summary.append((unique_hashes, labels.unique_hashes, None))
    summary.append((unique_pass, labels.unique_cracked, None))
    summary.append((f"{percent_unique:0.1f}%", labels.percent_unique, None))
    append_empty_password_summary(summary, main_list, settings)

    for group_name, _path in settings.group_lists:
        members = conn.execute(
            f"""
            SELECT h.username_full, h.sha1_hash_normal, h.sha1_hash_uppercase,
                   h.password, h.admin_status, h.login_enabled
            FROM hash_infos h
            {GROUP_MATCH_SQL}
            WHERE h.history_index = -1
            """,
            (group_name,),
        ).fetchall()
        new_list: list[tuple[object, ...]] = []
        for member in members:
            hash_to_check = member["sha1_hash_normal"] or member["sha1_hash_uppercase"]
            users_list = conn.execute(
                """
                SELECT username_full FROM hash_infos
                WHERE (sha1_hash_normal = ? OR sha1_hash_uppercase = ?) AND history_index = -1
                """,
                (hash_to_check, hash_to_check),
            ).fetchall()
            if len(users_list) < 30:
                shared = ", ".join(row[0] for row in users_list)
            else:
                shared = labels.too_many
            new_list.append(
                (
                    member["username_full"],
                    member["sha1_hash_normal"],
                    member["sha1_hash_uppercase"],
                    shared,
                    len(users_list),
                    display_password(member["password"], labels),
                    format_admin(member["admin_status"] or "False", labels),
                    format_login(member["login_enabled"] or "False", labels),
                )
            )
        new_list.sort(key=lambda item: password_key(item[5]) is not None, reverse=True)
        if new_list:
            page = new_builder(settings)
            page.add_table_to_html(
                new_list,
                [
                    labels.username,
                    labels.sha1_normal,
                    labels.sha1_upper,
                    labels.users_sharing_this,
                    labels.share_count,
                    labels.password,
                    labels.admin_status,
                    labels.login_status,
                ],
            )
            filename = page.write_html_report(f"{safe_filename(group_name)}_members.html")
            summary.append(
                (len(members), labels.members_of.format(group=group_name), labels.details_link(filename))
            )

    length_rows = conn.execute(
        """
        SELECT LENGTH(password) AS plen, COUNT(password)
        FROM hash_infos
        WHERE password IS NOT NULL AND history_index = -1 AND LENGTH(password) > 0
        GROUP BY plen
        ORDER BY plen
        """
    ).fetchall()
    if length_rows:
        length_table: list[tuple[object, ...]] = []
        for index, item in enumerate(length_rows):
            length = item[0]
            usernames = conn.execute(
                """
                SELECT username FROM hash_infos
                WHERE history_index = -1 AND LENGTH(password) = ?
                """,
                (length,),
            ).fetchall()
            username_rows = sorted((row[0],) for row in usernames)
            page = new_builder(settings)
            page.add_table_to_html(username_rows, [labels.users_with_length.format(length=length)])
            filename = page.write_html_report(f"{index}_length_usernames.html")
            length_table.append((item[0], item[1], labels.details_link(filename)))
        page = new_builder(settings)
        page.add_table_to_html(length_table, [labels.password_length, labels.count, labels.details], 2)
        by_count = conn.execute(
            """
            SELECT COUNT(password) AS count, LENGTH(password) AS plen
            FROM hash_infos
            WHERE password IS NOT NULL AND history_index = -1 AND LENGTH(password) > 0
            GROUP BY plen
            ORDER BY count DESC
            """
        ).fetchall()
        page.add_table_to_html(by_count, [labels.count, labels.password_length])
        filename = page.write_html_report("password_length_stats.html")
        summary.append((None, labels.length_stats, labels.details_link(filename)))

    tops = top_passwords(main_list, labels)
    if tops:
        page = new_builder(settings)
        page.add_table_to_html(tops, [labels.password, labels.count])
        filename = page.write_html_report("top_password_stats.html")
        summary.append((None, labels.top_stats, labels.details_link(filename)))

    reuse = write_reuse_details(conn, settings, None, "")
    if reuse:
        page = new_builder(settings)
        page.add_table_to_html(
            reuse,
            [labels.sha1_normal, labels.sha1_upper, labels.count, labels.password, labels.details],
            4,
        )
        filename = page.write_html_report("password_reuse_stats.html")
        summary.append((None, labels.reuse_stats, labels.details_link(filename)))

    print(LABELS["en"].generating_db, file=sys.stderr)
    databases = [row[0] for row in conn.execute("SELECT DISTINCT database_name FROM hash_infos ORDER BY database_name")]
    if databases:
        db_rows: list[tuple[object, ...]] = []
        for db_name in databases:
            total_users = conn.execute(
                "SELECT COUNT(*) FROM hash_infos WHERE database_name = ?",
                (db_name,),
            ).fetchone()[0]
            db_records = rows_to_hash_list(
                current_accounts(conn, "AND database_name = ?", (db_name,)), labels
            )
            db_cracked = cracked_count(db_records)
            percent = (db_cracked / float(total_users) * 100) if total_users else 0
            admin_count_db = sum(1 for row in db_records if row[5] == labels.admin_yes)
            disabled_count_db = sum(1 for row in db_records if row[6] == labels.login_no)
            db_hb = generate_db_statistics(conn, settings, db_name)
            db_filename = f"{safe_filename(db_name)}_statistics.html"
            db_hb.write_html_report(db_filename)
            db_rows.append(
                (
                    db_name,
                    total_users,
                    db_cracked,
                    f"{percent:0.1f}%",
                    admin_count_db,
                    disabled_count_db,
                    labels.details_link(db_filename),
                )
            )
        page = new_builder(settings)
        page.add_table_to_html(
            db_rows,
            [
                labels.database_name,
                labels.total_users,
                labels.cracked_count,
                labels.cracked_pct,
                labels.admin_accounts,
                labels.login_disabled,
                labels.statistics,
            ],
            6,
        )
        filename = page.write_html_report("database_statistics.html")
        summary.append((len(databases), labels.db_stats, labels.details_link(filename)))

    hb = new_builder(settings)
    hb.add_table_to_html(summary, labels.summary_headers, 2)
    hb.write_html_report(settings.output_file)
    report_path = settings.report_directory / settings.output_file
    print(
        LABELS["en"].report_written.format(name=settings.output_file, directory=settings.report_directory),
        file=sys.stderr,
    )
    return report_path


def run_audit(settings: Settings) -> Path:
    started = time.perf_counter()
    settings.report_directory.mkdir(parents=True, exist_ok=True)
    conn = connect_db(settings)
    try:
        init_schema(conn)
        cli = LABELS["en"]
        print(cli.reading_v8users.format(path=settings.v8users_file), file=sys.stderr)
        if settings.verbose:
            size = settings.v8users_file.stat().st_size if settings.v8users_file.is_file() else 0
            db_label = str(settings.db_path) if settings.write_db else ":memory:"
            print(f"v8users size: {size} bytes, sqlite: {db_label}", file=sys.stderr)
        line_count, inserted = import_v8users(conn, settings)
        print(cli.processed_lines.format(lines=line_count, inserted=inserted), file=sys.stderr)
        if settings.verbose:
            print(f"group files: {len(settings.group_lists)}", file=sys.stderr)
        import_groups(conn, settings)
        print(cli.reading_crack.format(path=settings.crack_file), file=sys.stderr)
        if settings.verbose and settings.crack_file.is_file():
            print(f"potfile size: {settings.crack_file.stat().st_size} bytes", file=sys.stderr)
        crack_count, pot_passwords = import_potfile(conn, settings)
        print(cli.found_matches.format(count=crack_count), file=sys.stderr)
        print(cli.trying_case, file=sys.stderr)
        cracked_uppercase = crack_case_variations(conn, pot_passwords)
        print(cli.cracked_case.format(count=cracked_uppercase), file=sys.stderr)
        conn.commit()
        report_path = generate_reports(conn, settings)
        if settings.verbose:
            print(f"elapsed: {time.perf_counter() - started:.2f}s", file=sys.stderr)
        return report_path
    except Exception:
        if settings.verbose:
            traceback.print_exc()
        raise
    finally:
        conn.close()


def prompt_open_report(report_path: Path, labels: Labels) -> None:
    if not sys.stdin.isatty():
        return
    print(labels.open_prompt)
    while True:
        try:
            response = input().strip().lower()
        except EOFError:
            return
        if response in ("", "y", "yes", "1", "true", "д", "да"):
            webbrowser.open(report_path.resolve().as_uri())
            return
        if response in ("n", "no", "0", "false", "н", "нет"):
            return
        print(labels.yes_no_hint)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "1C Password Audit Tool (1PAT): HTML password-audit report from a "
            "v8users table dump and a Hashcat potfile."
        )
    )
    parser.add_argument("-v", "--v8users", required=True, help="v8users dump (semicolon-separated)")
    parser.add_argument(
        "-c",
        "--crackfile",
        required=True,
        help="Password cracking output in Hashcat potfile form",
    )
    parser.add_argument(
        "-o",
        "--outputfile",
        default=DEFAULT_REPORT_NAME,
        help=f"HTML report file name, defaults to {DEFAULT_REPORT_NAME}",
    )
    parser.add_argument(
        "-d",
        "--reportdirectory",
        default=DEFAULT_REPORT_DIR,
        help=f"Folder for HTML files, defaults to {DEFAULT_REPORT_DIR}",
    )
    parser.add_argument(
        "-w",
        "--writedb",
        action="store_true",
        help=f'Write SQLite database to disk as "{DEFAULT_DB_NAME}"',
    )
    parser.add_argument(
        "-s",
        "--sanitize",
        action="store_true",
        help='Sanitize the report and prepend the directory with "Sanitized - "',
    )
    parser.add_argument(
        "-g",
        "--grouplists",
        nargs="*",
        help=(
            "Files with usernames of a group. The group name is taken from the file name. "
            'Example: -g "Administrators.txt"'
        ),
    )
    parser.add_argument(
        "--open",
        action="store_true",
        help="Open the HTML report in a browser after generation",
    )
    parser.add_argument(
        "--no-prompt",
        action="store_true",
        help="Do not ask whether to open the report",
    )
    parser.add_argument(
        "-l",
        "--lang",
        choices=("en", "ru"),
        default="ru",
        help="HTML report language: en or ru (default)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print extra diagnostic information. -v is already used for the v8users file",
    )
    return parser


def settings_from_args(args: argparse.Namespace) -> Settings:
    report_dir = args.reportdirectory
    if args.sanitize:
        report_dir = f"{report_dir} - Sanitized"
    groups: list[tuple[str, Path]] = []
    if args.grouplists:
        for groupfile in args.grouplists:
            path = Path(groupfile)
            groups.append((os.path.splitext(path.name)[0], path))
    return Settings(
        v8users_file=Path(args.v8users),
        crack_file=Path(args.crackfile),
        output_file=args.outputfile,
        report_directory=Path(report_dir),
        write_db=args.writedb,
        sanitize_output=args.sanitize,
        group_lists=groups,
        lang=args.lang,
        open_report=args.open,
        verbose=args.verbose,
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    settings = settings_from_args(args)
    report_path = run_audit(settings)
    if settings.open_report:
        webbrowser.open(report_path.resolve().as_uri())
    elif not getattr(args, "no_prompt", False):
        prompt_open_report(report_path, LABELS["en"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
