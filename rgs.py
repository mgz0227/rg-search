#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rgs.py

A fast local folder/file content search tool powered by ripgrep.

This single-file version keeps the original command-line workflow and merges the
Tkinter GUI into rgs.py.  It also adds precise A:B:C three-field searching for
locally authorized security testing and data review.

Normal CLI examples:
  python3 rgs.py -p /data -k password token secret -o result.jsonl --format jsonl
  python3 rgs.py -p /data --keyword-file keywords.txt -o result.csv --format csv

A:B:C field-search examples:
  python3 rgs.py -p ./samples.txt -k username --abc --field B -o result.csv
  python3 rgs.py -p ./data -k "example.com" --abc --field A --format csv
  python3 rgs.py -p ./data -k "^admin" --abc --field B --regex --format csv

GUI:
  python3 rgs.py --gui
"""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
import os
import queue
import re
import shlex
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter
from dataclasses import asdict, dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
except Exception:  # pragma: no cover - headless/minimal Python installs
    tk = None  # type: ignore[assignment]
    filedialog = None  # type: ignore[assignment]
    messagebox = None  # type: ignore[assignment]
    ttk = None  # type: ignore[assignment]

VERSION = "3.0.0"
APP_TITLE = "rg-search - A/B/C Field Search"
APP_VERSION = VERSION

SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
FIELD_LABEL_TO_VALUE = {
    "任意字段 A/B/C": "ANY",
    "A 字段": "A",
    "B 字段": "B",
    "C 字段": "C",
}
FIELD_VALUE_TO_LABEL = {value: label for label, value in FIELD_LABEL_TO_VALUE.items()}
EXPORT_LABEL_TO_VALUE = {
    "CSV 表格 (.csv)": "csv",
    "TXT 一行一个 A:B:C (.txt)": "txt",
}
EXPORT_VALUE_TO_LABEL = {value: label for label, value in EXPORT_LABEL_TO_VALUE.items()}
ABC_EXPORT_COLUMNS = ["A", "B", "C", "file", "line", "source_line", "matches"]


@dataclass
class Hit:
    file: str
    line: int
    column: int
    content: str
    matches: List[str]
    submatches: List[Dict[str, object]]
    absolute_offset: Optional[int] = None

    def to_record(self) -> Dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class TripleRow:
    """One parsed A/B/C row with source location retained for auditability."""

    a: str
    b: str
    c: str
    file: str = ""
    line: int = 0
    column: int = 1
    source_line: str = ""
    matches: Tuple[str, ...] = ()

    def to_record(self) -> Dict[str, object]:
        return {
            "A": self.a,
            "B": self.b,
            "C": self.c,
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "source_line": self.source_line,
            "matches": list(self.matches),
        }


@dataclass
class ABCSearchResult:
    rows: List[TripleRow]
    raw_matches: int
    parsed_triples: int
    field_hits: int
    duplicates_removed: int
    files_with_hits: int
    top_files: List[Dict[str, object]]
    elapsed_seconds: float
    limited: bool
    rg_return_code: Optional[int]
    rg_summary: Dict[str, object]
    command: str


class MemoryDeduper:
    def __init__(self) -> None:
        self._seen = set()

    def is_duplicate(self, key: str) -> bool:
        if key in self._seen:
            return True
        self._seen.add(key)
        return False

    def close(self) -> None:
        return None


class SQLiteDeduper:
    def __init__(self, db_path: Path, flush_every: int = 10000) -> None:
        self.db_path = db_path
        self.flush_every = max(1, flush_every)
        self.ops = 0
        self.conn = sqlite3.connect(str(db_path))
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA temp_store=MEMORY")
        self.conn.execute("CREATE TABLE IF NOT EXISTS seen (k TEXT PRIMARY KEY)")
        self.conn.commit()

    def is_duplicate(self, key: str) -> bool:
        cur = self.conn.execute("INSERT OR IGNORE INTO seen(k) VALUES (?)", (key,))
        self.ops += 1
        if self.ops % self.flush_every == 0:
            self.conn.commit()
        return cur.rowcount == 0

    def close(self) -> None:
        self.conn.commit()
        self.conn.close()


class ResultWriter:
    """Writer for the original non-A/B/C result formats."""

    def __init__(self, output: Path, fmt: str) -> None:
        self.output = output
        self.format = fmt
        self.tmp_output = output.with_name(output.name + ".tmp")
        self.fp = None
        self.csv_writer = None

    def __enter__(self) -> "ResultWriter":
        self.output.parent.mkdir(parents=True, exist_ok=True)
        if self.format == "csv":
            self.fp = open(self.tmp_output, "w", encoding="utf-8", newline="")
            self.csv_writer = csv.DictWriter(
                self.fp,
                fieldnames=["file", "line", "column", "matches", "content"],
                extrasaction="ignore",
            )
            self.csv_writer.writeheader()
        else:
            self.fp = open(self.tmp_output, "w", encoding="utf-8")
            if self.format == "md":
                self.fp.write("| file | line | column | matches | content |\n")
                self.fp.write("|---|---:|---:|---|---|\n")
        return self

    def write(self, hit: Hit) -> None:
        if self.fp is None:
            raise RuntimeError("writer is not open")
        if self.format == "jsonl":
            self.fp.write(json.dumps(hit.to_record(), ensure_ascii=False) + "\n")
            return
        if self.format == "csv":
            if self.csv_writer is None:
                raise RuntimeError("csv writer is not open")
            self.csv_writer.writerow(
                {
                    "file": hit.file,
                    "line": hit.line,
                    "column": hit.column,
                    "matches": ";".join(hit.matches),
                    "content": hit.content,
                }
            )
            return
        if self.format == "md":
            self.fp.write(
                f"| {md_escape(hit.file)} | {hit.line} | {hit.column} | "
                f"{md_escape(';'.join(hit.matches))} | {md_escape(hit.content)} |\n"
            )
            return
        self.fp.write(f"{hit.file}:{hit.line}:{hit.column}: {hit.content}\n")

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.fp is not None:
            self.fp.close()
        if exc_type is None:
            os.replace(self.tmp_output, self.output)
        else:
            safe_unlink(self.tmp_output)


class TripleWriter:
    """Writer for A/B/C table output."""

    def __init__(self, output: Path, fmt: str) -> None:
        self.output = output
        self.format = fmt
        self.tmp_output = output.with_name(output.name + ".tmp")
        self.fp = None
        self.csv_writer = None

    def __enter__(self) -> "TripleWriter":
        self.output.parent.mkdir(parents=True, exist_ok=True)
        if self.format == "csv":
            self.fp = open(self.tmp_output, "w", encoding="utf-8-sig", newline="")
            self.csv_writer = csv.DictWriter(self.fp, fieldnames=ABC_EXPORT_COLUMNS)
            self.csv_writer.writeheader()
        else:
            self.fp = open(self.tmp_output, "w", encoding="utf-8")
            if self.format == "md":
                self.fp.write("| A | B | C | file | line | matches |\n")
                self.fp.write("|---|---|---|---|---:|---|\n")
        return self

    def write(self, row: TripleRow) -> None:
        if self.fp is None:
            raise RuntimeError("writer is not open")
        if self.format == "jsonl":
            self.fp.write(json.dumps(row.to_record(), ensure_ascii=False) + "\n")
            return
        if self.format == "csv":
            if self.csv_writer is None:
                raise RuntimeError("csv writer is not open")
            self.csv_writer.writerow(row_to_export_dict(row))
            return
        if self.format == "md":
            self.fp.write(
                f"| {md_escape(row.a)} | {md_escape(row.b)} | {md_escape(row.c)} | "
                f"{md_escape(row.file)} | {row.line} | {md_escape(';'.join(row.matches))} |\n"
            )
            return
        self.fp.write(
            f"{sanitize_txt_part(row.a)}:{sanitize_txt_part(row.b)}:{sanitize_txt_part(row.c)}\n"
        )

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.fp is not None:
            self.fp.close()
        if exc_type is None:
            os.replace(self.tmp_output, self.output)
        else:
            safe_unlink(self.tmp_output)


def safe_unlink(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except TypeError:  # Python 3.7 compatibility
        if path.exists():
            path.unlink()


def md_escape(value: object) -> str:
    return str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def sanitize_txt_part(value: object) -> str:
    return str(value).replace("\r", " ").replace("\n", " ").strip()


def json_text(value: Dict[str, str]) -> str:
    if not isinstance(value, dict):
        return ""
    if "text" in value:
        return value["text"]
    if "bytes" in value:
        try:
            return base64.b64decode(value["bytes"]).decode("utf-8", "replace")
        except Exception:
            return ""
    return ""


def byte_offset_to_column(text: str, byte_offset: int) -> int:
    if byte_offset <= 0:
        return 1
    try:
        prefix = text.encode("utf-8", "surrogatepass")[:byte_offset].decode("utf-8", "ignore")
        return len(prefix) + 1
    except Exception:
        return byte_offset + 1


def hit_from_rg_match(data: Dict[str, object]) -> Hit:
    file_path = json_text(data.get("path", {}))  # type: ignore[arg-type]
    content = json_text(data.get("lines", {})).rstrip("\r\n")  # type: ignore[arg-type]
    line_number = int(data.get("line_number", 0) or 0)
    absolute_offset = data.get("absolute_offset")
    if not isinstance(absolute_offset, int):
        absolute_offset = None

    submatch_records: List[Dict[str, object]] = []
    matched_terms: List[str] = []
    first_start: Optional[int] = None
    for sub in data.get("submatches", []) or []:
        if not isinstance(sub, dict):
            continue
        start = int(sub.get("start", 0) or 0)
        end = int(sub.get("end", 0) or 0)
        match_text = json_text(sub.get("match", {}))  # type: ignore[arg-type]
        submatch_records.append({"start": start, "end": end, "text": match_text})
        if match_text:
            matched_terms.append(match_text)
        if first_start is None or start < first_start:
            first_start = start

    column = byte_offset_to_column(content, first_start or 0)
    return Hit(
        file=file_path,
        line=line_number,
        column=column,
        content=content,
        matches=unique_keep_order(matched_terms),
        submatches=submatch_records,
        absolute_offset=absolute_offset,
    )


def unique_keep_order(values: Iterable[str]) -> List[str]:
    seen = set()
    result: List[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def parse_multiline_values(text: str) -> List[str]:
    return unique_keep_order(line.strip() for line in text.splitlines() if line.strip())


def parse_keyword_values(text: str) -> List[str]:
    # One keyword per line.  Do not split on spaces because B/C fields may contain spaces.
    return parse_multiline_values(text)


def find_url_aware_separator(text: str) -> Optional[int]:
    """
    Find the separator between URL-like A and B in URL:B:C.

    The parser skips the scheme separator in https:// and skips likely numeric
    ports in the authority section, e.g. https://host:8443/path:user:pass.
    """
    match = SCHEME_RE.match(text)
    if not match:
        return None

    scan_start = match.end()
    first_pathish = len(text)
    for marker in ("/", "?", "#"):
        idx = text.find(marker, scan_start)
        if idx != -1:
            first_pathish = min(first_pathish, idx)

    idx = scan_start
    while True:
        idx = text.find(":", idx)
        if idx == -1:
            return None
        rest = text[idx + 1 :]
        next_colon = rest.find(":")
        if next_colon == -1:
            return None
        b_candidate = rest[:next_colon]
        if not b_candidate:
            idx += 1
            continue

        # Skip a likely URL port before path/query/fragment.
        if idx < first_pathish:
            authority_piece = text[idx + 1 : first_pathish]
            port_piece = authority_piece.split(":", 1)[0]
            if port_piece.isdigit():
                idx += 1
                continue
        return idx


def split_abc_line(line: str) -> Optional[Tuple[str, str, str]]:
    """
    Parse a three-part line into (A, B, C).

    Rules:
      - URL-like A fields keep the scheme separator, e.g. https://.
      - B is delimited by the first ':' after A.
      - Extra ':' characters after B belong to C, so C may contain ':'.
      - Non-URL lines fall back to split(':', 2).
    """
    text = line.strip()
    if not text or text.count(":") < 2:
        return None

    sep = find_url_aware_separator(text)
    if sep is not None:
        a = text[:sep].strip()
        rest = text[sep + 1 :]
        b, found, c = rest.partition(":")
        if found and a and b.strip():
            return a, b.strip(), c.strip()

    a, found, rest = text.partition(":")
    if not found:
        return None
    b, found, c = rest.partition(":")
    if not found:
        return None
    a, b, c = a.strip(), b.strip(), c.strip()
    if not a or not b:
        return None
    return a, b, c


class FieldMatcher:
    def __init__(self, keywords: Sequence[str], field: str, regex: bool, ignore_case: bool) -> None:
        self.keywords = list(keywords)
        self.field = field.upper()
        if self.field not in {"ANY", "A", "B", "C"}:
            raise ValueError("--field must be one of ANY, A, B, C")
        self.regex = regex
        self.ignore_case = ignore_case
        self._regexes: List[Tuple[str, re.Pattern[str]]] = []
        if regex:
            flags = re.IGNORECASE if ignore_case else 0
            for keyword in self.keywords:
                self._regexes.append((keyword, re.compile(keyword, flags)))
        else:
            self._needles = [k.casefold() if ignore_case else k for k in self.keywords]

    def _values_for_row(self, row: TripleRow) -> List[str]:
        if self.field == "A":
            return [row.a]
        if self.field == "B":
            return [row.b]
        if self.field == "C":
            return [row.c]
        return [row.a, row.b, row.c]

    def matched_terms(self, row: TripleRow) -> List[str]:
        values = self._values_for_row(row)
        matched: List[str] = []
        if self.regex:
            for label, pattern in self._regexes:
                if any(pattern.search(value) for value in values):
                    matched.append(label)
            return unique_keep_order(matched)

        haystacks = [value.casefold() for value in values] if self.ignore_case else values
        for original, needle in zip(self.keywords, self._needles):
            if any(needle in haystack for haystack in haystacks):
                matched.append(original)
        return unique_keep_order(matched)

    def matches(self, row: TripleRow) -> bool:
        return bool(self.matched_terms(row))


def should_ignore_case_for_fields(args: argparse.Namespace, keywords: Sequence[str]) -> bool:
    if args.ignore_case:
        return True
    if args.case_sensitive:
        return False
    # Smart-case: ignore case only when all keywords are lowercase/no-case.
    return not any(any(ch.isupper() for ch in keyword) for keyword in keywords)


def dedupe_and_sort_rows(rows: Iterable[TripleRow]) -> List[TripleRow]:
    """
    Sort and de-duplicate A/B/C rows using A -> B -> C comparison.

    Only exact duplicate triples are removed.  If A is the same but B or C is
    different, the row is retained.
    """
    sorted_rows = sorted(
        rows,
        key=lambda row: (
            row.a.casefold(),
            row.b.casefold(),
            row.c.casefold(),
            row.a,
            row.b,
            row.c,
            row.file,
            row.line,
        ),
    )
    seen = set()
    result: List[TripleRow] = []
    for row in sorted_rows:
        key = (row.a, row.b, row.c)
        if key in seen:
            continue
        seen.add(key)
        result.append(row)
    return result


def row_to_export_dict(row: TripleRow) -> Dict[str, object]:
    return {
        "A": row.a,
        "B": row.b,
        "C": row.c,
        "file": row.file,
        "line": row.line,
        "source_line": row.source_line,
        "matches": ";".join(row.matches),
    }


def export_rows_to_csv(path: Path, rows: Sequence[TripleRow]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8-sig", newline="") as fp:
        writer = csv.DictWriter(fp, fieldnames=ABC_EXPORT_COLUMNS)
        writer.writeheader()
        for row in rows:
            writer.writerow(row_to_export_dict(row))


def export_rows_to_txt(path: Path, rows: Sequence[TripleRow]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as fp:
        for row in rows:
            fp.write(f"{sanitize_txt_part(row.a)}:{sanitize_txt_part(row.b)}:{sanitize_txt_part(row.c)}\n")


def export_rows(path: Path, rows: Sequence[TripleRow], export_format: str) -> None:
    if export_format == "csv":
        export_rows_to_csv(path, rows)
    elif export_format == "txt":
        export_rows_to_txt(path, rows)
    else:
        raise ValueError(f"unsupported export format: {export_format}")


def normalize_for_dedupe(text: str, args: argparse.Namespace) -> str:
    value = text.strip() if args.dedupe_trim else text
    if args.dedupe_collapse_space:
        value = " ".join(value.split())
    if args.dedupe_ignore_case:
        value = value.casefold()
    return value


def make_dedupe_key(hit: Hit, args: argparse.Namespace) -> str:
    if args.dedupe == "none":
        return ""
    content = normalize_for_dedupe(hit.content, args)
    file_path = str(Path(hit.file).resolve()) if hit.file else ""
    if args.dedupe == "content":
        raw = content
    elif args.dedupe == "file-content":
        raw = f"{file_path}\0{content}"
    elif args.dedupe == "line":
        raw = f"{file_path}\0{hit.line}\0{content}"
    else:
        raw = f"{file_path}\0{hit.line}\0{content}"
    return hashlib.sha256(raw.encode("utf-8", "surrogatepass")).hexdigest()


def load_keywords(args: argparse.Namespace) -> List[str]:
    keywords: List[str] = []
    for item in args.keywords or []:
        if item:
            keywords.append(item)
    for file_name in args.keyword_file or []:
        path = Path(file_name)
        with open(path, "r", encoding="utf-8", errors="replace") as fp:
            for raw_line in fp:
                line = raw_line.rstrip("\r\n")
                if args.keep_empty_keywords:
                    keywords.append(line)
                else:
                    stripped = line.strip()
                    if stripped and not stripped.startswith("#"):
                        keywords.append(stripped)
    return unique_keep_order(keywords)


def create_pattern_file(keywords: Sequence[str]) -> Path:
    fp = tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", delete=False, prefix="rg_patterns_", suffix=".txt"
    )
    try:
        for keyword in keywords:
            fp.write(keyword.replace("\r", "").replace("\n", " ") + "\n")
        return Path(fp.name)
    finally:
        fp.close()


def expand_exclude_glob(pattern: str) -> List[str]:
    item = pattern[1:] if pattern.startswith("!") else pattern
    item = item.strip()
    if not item:
        return []
    candidates = [item]
    has_glob = any(ch in item for ch in "*?[")
    if not has_glob and not item.endswith("/**"):
        candidates.append(item.rstrip("/") + "/**")
    expanded: List[str] = []
    for candidate in candidates:
        expanded.append(candidate)
        if not candidate.startswith("**/") and not candidate.startswith("/"):
            expanded.append("**/" + candidate)
    return unique_keep_order(expanded)


def add_common_rg_options(cmd: List[str], args: argparse.Namespace) -> None:
    if args.mmap:
        cmd.append("--mmap")
    if args.all:
        cmd.extend(["--hidden", "--no-ignore", "--text"])
    else:
        if args.hidden:
            cmd.append("--hidden")
        if args.no_ignore:
            cmd.append("--no-ignore")
        if args.text:
            cmd.append("--text")
    if args.follow:
        cmd.append("--follow")
    if args.max_filesize:
        cmd.extend(["--max-filesize", str(args.max_filesize)])
    if args.max_columns:
        cmd.extend(["--max-columns", str(args.max_columns)])
    if args.max_count_per_file:
        cmd.extend(["--max-count", str(args.max_count_per_file)])
    for item in args.glob or []:
        cmd.extend(["--glob", item])
    for item in args.exclude or []:
        for expanded in expand_exclude_glob(item):
            cmd.extend(["--glob", f"!{expanded}"])


def build_rg_cmd(args: argparse.Namespace, pattern_file: Path) -> List[str]:
    cmd = [
        args.rg_bin,
        "--json",
        "--line-number",
        "--column",
        "--with-filename",
        "--color",
        "never",
        "--threads",
        str(args.threads),
    ]
    add_common_rg_options(cmd, args)
    if args.regex:
        if args.multiline:
            cmd.append("--multiline")
    else:
        cmd.append("--fixed-strings")
    if args.ignore_case:
        cmd.append("--ignore-case")
    elif args.case_sensitive:
        cmd.append("--case-sensitive")
    else:
        cmd.append("--smart-case")
    cmd.extend(["--file", str(pattern_file)])
    cmd.extend(args.path)
    return cmd


def build_abc_candidate_rg_cmd(args: argparse.Namespace, pattern_file: Path) -> List[str]:
    """Use ripgrep to stream lines containing ':'; field filtering happens in Python."""
    cmd = [
        args.rg_bin,
        "--json",
        "--line-number",
        "--column",
        "--with-filename",
        "--color",
        "never",
        "--threads",
        str(args.threads),
    ]
    add_common_rg_options(cmd, args)
    cmd.extend(["--fixed-strings", "--case-sensitive", "--file", str(pattern_file)])
    cmd.extend(args.path)
    return cmd


def validate_common_args(args: argparse.Namespace) -> None:
    resolved_rg = shutil.which(args.rg_bin)
    args.rg_bin = resolved_rg or args.rg_bin
    if resolved_rg is None and not Path(args.rg_bin).exists():
        raise SystemExit("ripgrep executable not found. Install rg or pass --rg-bin /path/to/rg")
    if not args.path:
        raise SystemExit("search path is required; use -p/--path or launch GUI with --gui")
    for item in args.path:
        if not Path(item).exists():
            raise SystemExit(f"search path does not exist: {item}")
    if args.threads < 0:
        raise SystemExit("--threads must be >= 0")
    if args.limit is not None and args.limit <= 0:
        raise SystemExit("--limit must be > 0")
    if args.progress_every <= 0:
        raise SystemExit("--progress-every must be > 0")


def make_deduper(args: argparse.Namespace, output_path: Path):
    if args.dedupe == "none":
        return None, None
    if args.dedupe_store == "memory":
        return MemoryDeduper(), None
    db_path = Path(args.dedupe_db) if args.dedupe_db else output_path.with_suffix(output_path.suffix + ".dedupe.sqlite")
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return SQLiteDeduper(db_path, flush_every=args.flush_every), db_path


def print_progress(raw_matches: int, written: int, duplicates: int, started: float) -> None:
    elapsed = max(time.time() - started, 0.001)
    rate = raw_matches / elapsed
    print(
        f"progress raw={raw_matches:,} unique={written:,} dup={duplicates:,} "
        f"elapsed={elapsed:.1f}s rate={rate:,.0f}/s",
        flush=True,
    )


def write_summary(path: Path, summary: Dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as fp:
        json.dump(summary, fp, ensure_ascii=False, indent=2)
        fp.write("\n")
    os.replace(tmp, path)


def run_normal_cli(args: argparse.Namespace) -> int:
    validate_common_args(args)
    keywords = load_keywords(args)
    if not keywords:
        raise SystemExit("no keywords or patterns provided; use -k or --keyword-file")

    output_path = Path(args.output).resolve()
    summary_path = None
    if not args.no_summary:
        summary_path = Path(args.summary).resolve() if args.summary else output_path.with_suffix(output_path.suffix + ".summary.json")

    pattern_file = create_pattern_file(keywords)
    deduper = None
    dedupe_db_path = None
    raw_matches = 0
    written = 0
    duplicates = 0
    file_counts: Counter[str] = Counter()
    rg_summary: Dict[str, object] = {}
    limited = False
    return_code = None
    started = time.time()
    cmd: List[str] = []

    try:
        cmd = build_rg_cmd(args, pattern_file)
        deduper, dedupe_db_path = make_deduper(args, output_path)
        if not args.quiet:
            print(f"rg-search v{VERSION}")
            print(f"keywords={len(keywords):,} mode={'regex' if args.regex else 'fixed'} dedupe={args.dedupe}")
            print(f"output={output_path}")
        if args.debug:
            print("cmd=" + shlex.join(cmd))

        stderr_target = None if args.debug else subprocess.DEVNULL
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=stderr_target,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        assert proc.stdout is not None
        with ResultWriter(output_path, args.format) as writer:
            for raw_line in proc.stdout:
                try:
                    obj = json.loads(raw_line)
                except json.JSONDecodeError:
                    continue
                obj_type = obj.get("type")
                if obj_type == "summary":
                    data = obj.get("data", {})
                    if isinstance(data, dict):
                        rg_summary = data
                    continue
                if obj_type != "match":
                    continue
                data = obj.get("data", {})
                if not isinstance(data, dict):
                    continue
                raw_matches += 1
                hit = hit_from_rg_match(data)

                if args.dedupe != "none" and deduper is not None:
                    key = make_dedupe_key(hit, args)
                    if deduper.is_duplicate(key):
                        duplicates += 1
                        if not args.quiet and raw_matches % args.progress_every == 0:
                            print_progress(raw_matches, written, duplicates, started)
                        continue

                writer.write(hit)
                written += 1
                file_counts[hit.file] += 1
                if not args.quiet and raw_matches % args.progress_every == 0:
                    print_progress(raw_matches, written, duplicates, started)
                if args.limit is not None and written >= args.limit:
                    limited = True
                    proc.terminate()
                    break

        try:
            return_code = proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            return_code = proc.wait(timeout=5)
    finally:
        if deduper is not None:
            deduper.close()
        safe_unlink(pattern_file)
        if dedupe_db_path and not args.keep_dedupe_db and not args.dedupe_db:
            for candidate in [
                dedupe_db_path,
                Path(str(dedupe_db_path) + "-wal"),
                Path(str(dedupe_db_path) + "-shm"),
            ]:
                safe_unlink(candidate)

    elapsed = time.time() - started
    summary = {
        "version": VERSION,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "mode": "normal",
        "path": args.path,
        "output": str(output_path),
        "format": args.format,
        "keywords_count": len(keywords),
        "search_mode": "regex" if args.regex else "fixed",
        "dedupe": args.dedupe,
        "dedupe_store": args.dedupe_store if args.dedupe != "none" else "none",
        "raw_matches": raw_matches,
        "written_results": written,
        "duplicates_removed": duplicates,
        "files_with_written_hits": len(file_counts),
        "top_files": [{"file": file, "hits": count} for file, count in file_counts.most_common(20)],
        "elapsed_seconds": round(elapsed, 3),
        "raw_matches_per_second": round(raw_matches / elapsed, 2) if elapsed > 0 else raw_matches,
        "limited": limited,
        "rg_return_code": return_code,
        "rg_summary": rg_summary,
        "command": shlex.join(cmd) if cmd else "",
    }
    if summary_path is not None:
        write_summary(summary_path, summary)
    if not args.quiet:
        print(f"done raw={raw_matches:,} unique={written:,} dup={duplicates:,} elapsed={elapsed:.2f}s")
        if summary_path is not None:
            print(f"summary={summary_path}")
    if limited:
        return 0
    if return_code in (0, 1, None):
        return 0
    return int(return_code)


def search_abc_rows(
    args: argparse.Namespace,
    keywords: Sequence[str],
    progress: Optional[Callable[[str], None]] = None,
    cancel_event: Optional[threading.Event] = None,
) -> ABCSearchResult:
    ignore_case = should_ignore_case_for_fields(args, keywords)
    try:
        matcher = FieldMatcher(keywords, args.field, args.regex, ignore_case)
    except re.error as exc:
        raise ValueError(f"invalid regex: {exc}") from exc

    candidate_pattern_file = create_pattern_file([":"])
    rows: List[TripleRow] = []
    raw_matches = 0
    parsed_triples = 0
    field_hits = 0
    file_counts: Counter[str] = Counter()
    rg_summary: Dict[str, object] = {}
    return_code: Optional[int] = None
    started = time.time()
    cmd: List[str] = []

    def emit(message: str) -> None:
        if progress is not None:
            progress(message)

    try:
        cmd = build_abc_candidate_rg_cmd(args, candidate_pattern_file)
        if args.debug:
            emit("cmd=" + shlex.join(cmd))
        stderr_target = None if args.debug else subprocess.DEVNULL
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=stderr_target,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        assert proc.stdout is not None
        for raw_line in proc.stdout:
            if cancel_event is not None and cancel_event.is_set():
                proc.terminate()
                raise RuntimeError("search cancelled")
            try:
                obj = json.loads(raw_line)
            except json.JSONDecodeError:
                continue
            obj_type = obj.get("type")
            if obj_type == "summary":
                data = obj.get("data", {})
                if isinstance(data, dict):
                    rg_summary = data
                continue
            if obj_type != "match":
                continue
            data = obj.get("data", {})
            if not isinstance(data, dict):
                continue
            raw_matches += 1
            hit = hit_from_rg_match(data)
            parsed = split_abc_line(hit.content)
            if parsed is None:
                if not args.quiet and raw_matches % args.progress_every == 0:
                    emit(f"progress raw={raw_matches:,} parsed={parsed_triples:,} matched={field_hits:,}")
                continue
            parsed_triples += 1
            a, b, c = parsed
            row = TripleRow(
                a=a,
                b=b,
                c=c,
                file=hit.file,
                line=hit.line,
                column=hit.column,
                source_line=hit.content,
            )
            matched_terms = matcher.matched_terms(row)
            if matched_terms:
                row = replace(row, matches=tuple(matched_terms))
                rows.append(row)
                field_hits += 1
                file_counts[row.file] += 1
            if not args.quiet and raw_matches % args.progress_every == 0:
                emit(f"progress raw={raw_matches:,} parsed={parsed_triples:,} matched={field_hits:,}")

        try:
            return_code = proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            return_code = proc.wait(timeout=5)
    finally:
        safe_unlink(candidate_pattern_file)

    deduped_rows = dedupe_and_sort_rows(rows)
    duplicates_removed = len(rows) - len(deduped_rows)
    limited = False
    if args.limit is not None and len(deduped_rows) > args.limit:
        deduped_rows = deduped_rows[: args.limit]
        limited = True
    elapsed = time.time() - started
    return ABCSearchResult(
        rows=deduped_rows,
        raw_matches=raw_matches,
        parsed_triples=parsed_triples,
        field_hits=field_hits,
        duplicates_removed=duplicates_removed,
        files_with_hits=len(file_counts),
        top_files=[{"file": file, "hits": count} for file, count in file_counts.most_common(20)],
        elapsed_seconds=elapsed,
        limited=limited,
        rg_return_code=return_code,
        rg_summary=rg_summary,
        command=shlex.join(cmd) if cmd else "",
    )


def run_abc_cli(args: argparse.Namespace) -> int:
    validate_common_args(args)
    keywords = load_keywords(args)
    if not keywords:
        raise SystemExit("no keywords or patterns provided; use -k or --keyword-file")

    output_path = Path(args.output).resolve()
    summary_path = None
    if not args.no_summary:
        summary_path = Path(args.summary).resolve() if args.summary else output_path.with_suffix(output_path.suffix + ".summary.json")

    if not args.quiet:
        print(f"rg-search v{VERSION} A/B/C mode")
        print(
            f"keywords={len(keywords):,} field={args.field} mode={'regex' if args.regex else 'fixed'} "
            f"dedupe=A->B->C"
        )
        print(f"output={output_path}")
        print("A/B/C field filtering is applied after parsing candidate lines, so B/C regex anchors are field-accurate.")

    result = search_abc_rows(
        args,
        keywords,
        progress=(lambda msg: print(msg, flush=True)) if not args.quiet else None,
    )

    with TripleWriter(output_path, args.format) as writer:
        for row in result.rows:
            writer.write(row)

    summary = {
        "version": VERSION,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "mode": "abc",
        "path": args.path,
        "output": str(output_path),
        "format": args.format,
        "keywords_count": len(keywords),
        "field": args.field,
        "search_mode": "regex" if args.regex else "fixed",
        "dedupe": "A->B->C exact triple",
        "raw_candidate_lines": result.raw_matches,
        "parsed_triples": result.parsed_triples,
        "field_hits_before_dedupe": result.field_hits,
        "written_results": len(result.rows),
        "duplicates_removed": result.duplicates_removed,
        "files_with_written_hits": result.files_with_hits,
        "top_files": result.top_files,
        "elapsed_seconds": round(result.elapsed_seconds, 3),
        "limited": result.limited,
        "rg_return_code": result.rg_return_code,
        "rg_summary": result.rg_summary,
        "command": result.command,
    }
    if summary_path is not None:
        write_summary(summary_path, summary)
    if not args.quiet:
        print(
            f"done raw={result.raw_matches:,} parsed={result.parsed_triples:,} "
            f"matched={result.field_hits:,} written={len(result.rows):,} "
            f"dup={result.duplicates_removed:,} elapsed={result.elapsed_seconds:.2f}s"
        )
        if summary_path is not None:
            print(f"summary={summary_path}")
    if result.rg_return_code in (0, 1, None):
        return 0
    return int(result.rg_return_code)


@dataclass
class GuiSearchConfig:
    paths: List[str]
    keywords: List[str]
    field: str
    regex: bool
    ignore_case: bool
    all_files: bool
    rg_bin: str
    include_globs: List[str]
    exclude_globs: List[str]
    max_filesize: str
    max_columns: str
    max_count_per_file: str
    output_limit: int


def int_or_none(value: str, label: str) -> Optional[int]:
    value = value.strip()
    if not value:
        return None
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ValueError(f"{label} 必须是整数。") from exc
    if parsed <= 0:
        raise ValueError(f"{label} 必须大于 0。")
    return parsed


def args_from_gui_config(config: GuiSearchConfig) -> argparse.Namespace:
    return argparse.Namespace(
        path=config.paths,
        keywords=config.keywords,
        keyword_file=[],
        keep_empty_keywords=False,
        output="rg_abc_results.csv",
        format="csv",
        summary=None,
        no_summary=True,
        regex=config.regex,
        multiline=False,
        ignore_case=config.ignore_case,
        case_sensitive=not config.ignore_case,
        smart_case=False,
        glob=config.include_globs,
        exclude=config.exclude_globs,
        all=config.all_files,
        hidden=False,
        no_ignore=False,
        text=False,
        follow=False,
        mmap=True,
        threads=0,
        max_filesize=config.max_filesize or None,
        max_columns=int_or_none(config.max_columns, "max-columns"),
        max_count_per_file=int_or_none(config.max_count_per_file, "每文件最大命中"),
        limit=config.output_limit if config.output_limit > 0 else None,
        dedupe="none",
        dedupe_store="memory",
        dedupe_db=None,
        keep_dedupe_db=False,
        dedupe_trim=True,
        dedupe_collapse_space=False,
        dedupe_ignore_case=False,
        flush_every=10000,
        progress_every=10000,
        quiet=True,
        debug=False,
        rg_bin=config.rg_bin or "rg",
        abc=True,
        field=config.field,
    )


def run_gui_search(
    config: GuiSearchConfig,
    progress: Callable[[str], None],
    cancel_event: threading.Event,
) -> List[TripleRow]:
    if not config.paths:
        raise ValueError("至少需要选择一个要检索的文件或目录。")
    if not config.keywords:
        raise ValueError("至少需要输入一个关键词。")
    args = args_from_gui_config(config)
    validate_common_args(args)
    progress("开始本地 A/B/C 三段式检索。")
    progress("会先解析 A:B:C，再按所选字段过滤；结果按 A -> B -> C 排序去重。")
    result = search_abc_rows(args, config.keywords, progress=progress, cancel_event=cancel_event)
    progress(
        f"候选行 {result.raw_matches:,}；可解析三段式 {result.parsed_triples:,}；"
        f"字段命中 {result.field_hits:,}。"
    )
    progress(f"按 A -> B -> C 去重完成，移除 {result.duplicates_removed:,} 条重复记录。")
    if result.limited:
        progress(f"结果已按显示上限截断为 {len(result.rows):,} 条。")
    return result.rows


class RgSearchGui(tk.Tk):  # type: ignore[misc, valid-type]
    def __init__(self) -> None:
        super().__init__()
        self.title(f"{APP_TITLE} v{APP_VERSION}")
        self.geometry("1180x760")
        self.minsize(980, 620)
        self.event_queue: queue.Queue[Tuple[str, object]] = queue.Queue()
        self.cancel_event = threading.Event()
        self.worker_thread: Optional[threading.Thread] = None
        self.rows: List[TripleRow] = []
        self._build_variables()
        self._build_layout()
        self.after(100, self._poll_events)

    def _build_variables(self) -> None:
        self.field_var = tk.StringVar(value=FIELD_VALUE_TO_LABEL["B"])
        self.regex_var = tk.BooleanVar(value=False)
        self.ignore_case_var = tk.BooleanVar(value=True)
        self.all_files_var = tk.BooleanVar(value=False)
        self.rg_bin_var = tk.StringVar(value="rg")
        self.max_filesize_var = tk.StringVar(value="")
        self.max_columns_var = tk.StringVar(value="")
        self.max_count_var = tk.StringVar(value="")
        self.output_limit_var = tk.StringVar(value="0")
        self.export_format_var = tk.StringVar(value=EXPORT_VALUE_TO_LABEL["csv"])
        self.status_var = tk.StringVar(value="就绪")

    def _build_layout(self) -> None:
        root = ttk.Frame(self, padding=10)
        root.pack(fill=tk.BOTH, expand=True)
        root.columnconfigure(0, weight=0)
        root.columnconfigure(1, weight=1)
        root.rowconfigure(6, weight=1)

        ttk.Label(root, text="检索路径\n一行一个文件或目录").grid(row=0, column=0, sticky=tk.NW, pady=3)
        path_frame = ttk.Frame(root)
        path_frame.grid(row=0, column=1, sticky=tk.EW, pady=3)
        path_frame.columnconfigure(0, weight=1)
        self.paths_text = tk.Text(path_frame, height=3, wrap=tk.NONE)
        self.paths_text.grid(row=0, column=0, sticky=tk.EW)
        path_buttons = ttk.Frame(path_frame)
        path_buttons.grid(row=0, column=1, sticky=tk.N, padx=(6, 0))
        ttk.Button(path_buttons, text="添加目录", command=self._add_directory).pack(fill=tk.X)
        ttk.Button(path_buttons, text="添加文件", command=self._add_file).pack(fill=tk.X, pady=(4, 0))
        ttk.Button(path_buttons, text="清空路径", command=lambda: self.paths_text.delete("1.0", tk.END)).pack(
            fill=tk.X, pady=(4, 0)
        )

        ttk.Label(root, text="关键词\n一行一个").grid(row=1, column=0, sticky=tk.NW, pady=3)
        self.keywords_text = tk.Text(root, height=3, wrap=tk.NONE)
        self.keywords_text.grid(row=1, column=1, sticky=tk.EW, pady=3)

        options = ttk.LabelFrame(root, text="A/B/C 字段检索选项")
        options.grid(row=2, column=0, columnspan=2, sticky=tk.EW, pady=(8, 4))
        options.columnconfigure(9, weight=1)
        ttk.Label(options, text="字段").grid(row=0, column=0, sticky=tk.W, padx=(8, 4), pady=6)
        field_combo = ttk.Combobox(
            options,
            textvariable=self.field_var,
            values=list(FIELD_LABEL_TO_VALUE.keys()),
            state="readonly",
            width=18,
        )
        field_combo.grid(row=0, column=1, sticky=tk.W, padx=(0, 12), pady=6)
        ttk.Checkbutton(options, text="正则", variable=self.regex_var).grid(
            row=0, column=2, sticky=tk.W, padx=(0, 12), pady=6
        )
        ttk.Checkbutton(options, text="忽略大小写", variable=self.ignore_case_var).grid(
            row=0, column=3, sticky=tk.W, padx=(0, 12), pady=6
        )
        ttk.Checkbutton(options, text="扫描隐藏/忽略/二进制文本", variable=self.all_files_var).grid(
            row=0, column=4, sticky=tk.W, padx=(0, 12), pady=6
        )
        ttk.Label(options, text="rg").grid(row=0, column=5, sticky=tk.W, padx=(0, 4), pady=6)
        ttk.Entry(options, textvariable=self.rg_bin_var, width=12).grid(
            row=0, column=6, sticky=tk.W, padx=(0, 12), pady=6
        )

        filters = ttk.LabelFrame(root, text="可选过滤 / 性能参数")
        filters.grid(row=3, column=0, columnspan=2, sticky=tk.EW, pady=(4, 4))
        filters.columnconfigure(1, weight=1)
        filters.columnconfigure(3, weight=1)
        ttk.Label(filters, text="include glob\n一行一个").grid(row=0, column=0, sticky=tk.NW, padx=(8, 4), pady=6)
        self.include_text = tk.Text(filters, height=2, wrap=tk.NONE)
        self.include_text.grid(row=0, column=1, sticky=tk.EW, padx=(0, 8), pady=6)
        ttk.Label(filters, text="exclude glob\n一行一个").grid(row=0, column=2, sticky=tk.NW, padx=(8, 4), pady=6)
        self.exclude_text = tk.Text(filters, height=2, wrap=tk.NONE)
        self.exclude_text.grid(row=0, column=3, sticky=tk.EW, padx=(0, 8), pady=6)

        perf = ttk.Frame(filters)
        perf.grid(row=1, column=0, columnspan=4, sticky=tk.EW, padx=8, pady=(0, 6))
        ttk.Label(perf, text="max-filesize").pack(side=tk.LEFT)
        ttk.Entry(perf, textvariable=self.max_filesize_var, width=10).pack(side=tk.LEFT, padx=(4, 14))
        ttk.Label(perf, text="max-columns").pack(side=tk.LEFT)
        ttk.Entry(perf, textvariable=self.max_columns_var, width=8).pack(side=tk.LEFT, padx=(4, 14))
        ttk.Label(perf, text="每文件最大命中").pack(side=tk.LEFT)
        ttk.Entry(perf, textvariable=self.max_count_var, width=8).pack(side=tk.LEFT, padx=(4, 14))
        ttk.Label(perf, text="显示上限 0=不限").pack(side=tk.LEFT)
        ttk.Entry(perf, textvariable=self.output_limit_var, width=8).pack(side=tk.LEFT, padx=(4, 14))

        button_frame = ttk.Frame(root)
        button_frame.grid(row=4, column=0, columnspan=2, sticky=tk.EW, pady=6)
        self.start_button = ttk.Button(button_frame, text="开始检索", command=self._start_search)
        self.start_button.pack(side=tk.LEFT)
        self.cancel_button = ttk.Button(button_frame, text="取消", command=self._cancel_search, state=tk.DISABLED)
        self.cancel_button.pack(side=tk.LEFT, padx=(8, 0))
        ttk.Label(button_frame, text="导出格式").pack(side=tk.LEFT, padx=(14, 4))
        export_combo = ttk.Combobox(
            button_frame,
            textvariable=self.export_format_var,
            values=list(EXPORT_LABEL_TO_VALUE.keys()),
            state="readonly",
            width=24,
        )
        export_combo.pack(side=tk.LEFT)
        self.export_button = ttk.Button(button_frame, text="导出结果", command=self._export_results, state=tk.DISABLED)
        self.export_button.pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(button_frame, text="清空结果", command=self._clear_results).pack(side=tk.LEFT, padx=(8, 0))

        ttk.Label(root, textvariable=self.status_var).grid(row=5, column=0, columnspan=2, sticky=tk.EW, pady=(2, 6))

        result_pane = ttk.Panedwindow(root, orient=tk.VERTICAL)
        result_pane.grid(row=6, column=0, columnspan=2, sticky=tk.NSEW)

        table_frame = ttk.Frame(result_pane)
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)
        self.tree = ttk.Treeview(table_frame, columns=("A", "B", "C", "file", "line"), show="headings")
        for column, width in (("A", 330), ("B", 210), ("C", 260), ("file", 260), ("line", 70)):
            self.tree.heading(column, text=column)
            self.tree.column(column, width=width, minwidth=60, stretch=True)
        yscroll = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        xscroll = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        self.tree.grid(row=0, column=0, sticky=tk.NSEW)
        yscroll.grid(row=0, column=1, sticky=tk.NS)
        xscroll.grid(row=1, column=0, sticky=tk.EW)
        result_pane.add(table_frame, weight=4)

        log_frame = ttk.Frame(result_pane)
        log_frame.rowconfigure(0, weight=1)
        log_frame.columnconfigure(0, weight=1)
        self.log_text = tk.Text(log_frame, height=6, wrap=tk.WORD, state=tk.DISABLED)
        log_scroll = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scroll.set)
        self.log_text.grid(row=0, column=0, sticky=tk.NSEW)
        log_scroll.grid(row=0, column=1, sticky=tk.NS)
        result_pane.add(log_frame, weight=1)

    def _add_directory(self) -> None:
        path = filedialog.askdirectory(title="选择要检索的目录")
        if path:
            self._append_path(path)

    def _add_file(self) -> None:
        path = filedialog.askopenfilename(title="选择要检索的文件", filetypes=[("All files", "*")])
        if path:
            self._append_path(path)

    def _append_path(self, path: str) -> None:
        current = self.paths_text.get("1.0", tk.END).strip()
        if current:
            self.paths_text.insert(tk.END, "\n" + path)
        else:
            self.paths_text.insert(tk.END, path)

    def _make_config(self) -> GuiSearchConfig:
        paths = parse_multiline_values(self.paths_text.get("1.0", tk.END))
        keywords = parse_keyword_values(self.keywords_text.get("1.0", tk.END))
        field = FIELD_LABEL_TO_VALUE.get(self.field_var.get(), "B")
        try:
            output_limit = int(self.output_limit_var.get().strip() or "0")
        except ValueError as exc:
            raise ValueError("显示上限必须是整数。") from exc
        if output_limit < 0:
            raise ValueError("显示上限不能小于 0。")
        return GuiSearchConfig(
            paths=paths,
            keywords=keywords,
            field=field,
            regex=self.regex_var.get(),
            ignore_case=self.ignore_case_var.get(),
            all_files=self.all_files_var.get(),
            rg_bin=self.rg_bin_var.get().strip() or "rg",
            include_globs=parse_multiline_values(self.include_text.get("1.0", tk.END)),
            exclude_globs=parse_multiline_values(self.exclude_text.get("1.0", tk.END)),
            max_filesize=self.max_filesize_var.get().strip(),
            max_columns=self.max_columns_var.get().strip(),
            max_count_per_file=self.max_count_var.get().strip(),
            output_limit=output_limit,
        )

    def _start_search(self) -> None:
        if self.worker_thread and self.worker_thread.is_alive():
            messagebox.showinfo("检索中", "当前检索尚未结束。")
            return
        try:
            config = self._make_config()
        except Exception as exc:
            messagebox.showerror("参数错误", str(exc))
            return
        self._clear_results(clear_log=False)
        self.cancel_event.clear()
        self.start_button.configure(state=tk.DISABLED)
        self.cancel_button.configure(state=tk.NORMAL)
        self.export_button.configure(state=tk.DISABLED)
        self.status_var.set("检索中...")
        self._log("开始检索。")

        def worker() -> None:
            try:
                rows = run_gui_search(config, lambda msg: self.event_queue.put(("log", msg)), self.cancel_event)
                self.event_queue.put(("done", rows))
            except Exception as exc:
                self.event_queue.put(("error", str(exc)))

        self.worker_thread = threading.Thread(target=worker, daemon=True)
        self.worker_thread.start()

    def _cancel_search(self) -> None:
        self.cancel_event.set()
        self.status_var.set("正在取消...")

    def _clear_results(self, clear_log: bool = True) -> None:
        self.rows = []
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.export_button.configure(state=tk.DISABLED)
        self.status_var.set("就绪")
        if clear_log:
            self.log_text.configure(state=tk.NORMAL)
            self.log_text.delete("1.0", tk.END)
            self.log_text.configure(state=tk.DISABLED)

    def _export_results(self) -> None:
        if not self.rows:
            messagebox.showinfo("无结果", "当前没有可导出的结果。")
            return
        export_format = EXPORT_LABEL_TO_VALUE.get(self.export_format_var.get(), "csv")
        if export_format == "txt":
            title = "导出 TXT：一行一个 A:B:C"
            extension = ".txt"
            filetypes = [("TXT", "*.txt"), ("CSV", "*.csv"), ("All files", "*")]
        else:
            title = "导出 CSV 表格"
            extension = ".csv"
            filetypes = [("CSV", "*.csv"), ("TXT", "*.txt"), ("All files", "*")]
        path = filedialog.asksaveasfilename(title=title, defaultextension=extension, filetypes=filetypes)
        if not path:
            return
        try:
            export_rows(Path(path), self.rows, export_format)
        except Exception as exc:
            messagebox.showerror("导出失败", str(exc))
            return
        messagebox.showinfo("导出完成", f"已按 {export_format.upper()} 格式导出 {len(self.rows):,} 条结果。")

    def _insert_rows(self, rows: Sequence[TripleRow]) -> None:
        self.rows = list(rows)
        for row in self.rows:
            self.tree.insert("", tk.END, values=(row.a, row.b, row.c, row.file, row.line))
        self.export_button.configure(state=tk.NORMAL if self.rows else tk.DISABLED)

    def _log(self, message: str) -> None:
        timestamp = time.strftime("%H:%M:%S")
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)

    def _poll_events(self) -> None:
        try:
            while True:
                event, payload = self.event_queue.get_nowait()
                if event == "log":
                    self._log(str(payload))
                elif event == "done":
                    rows = payload if isinstance(payload, list) else []
                    self._insert_rows(rows)
                    self.status_var.set(f"完成：{len(rows):,} 条去重后结果")
                    self._log(f"完成：{len(rows):,} 条去重后结果。")
                    self.start_button.configure(state=tk.NORMAL)
                    self.cancel_button.configure(state=tk.DISABLED)
                elif event == "error":
                    message = str(payload)
                    self.status_var.set("失败或已取消")
                    self._log(message)
                    messagebox.showerror("检索失败", message)
                    self.start_button.configure(state=tk.NORMAL)
                    self.cancel_button.configure(state=tk.DISABLED)
        except queue.Empty:
            pass
        self.after(100, self._poll_events)


def run_gui() -> int:
    if tk is None:
        raise SystemExit("tkinter is not available. Install python3-tk or use CLI mode.")
    app = RgSearchGui()
    app.mainloop()
    return 0


def run_self_test() -> int:
    samples = [
        ("https://example.test/path:user1:pass1", ("https://example.test/path", "user1", "pass1")),
        ("https://example.test/path/:user2:pa:ss:2", ("https://example.test/path/", "user2", "pa:ss:2")),
        ("https://example.test:8443/path:user3:pass3", ("https://example.test:8443/path", "user3", "pass3")),
        ("https://www.kenhub.com/:Cloud Link - TG-ABC:def", ("https://www.kenhub.com/", "Cloud Link - TG-ABC", "def")),
        ("plainA:plainB:plainC:tail", ("plainA", "plainB", "plainC:tail")),
    ]
    for line, expected in samples:
        actual = split_abc_line(line)
        if actual != expected:
            print(f"FAILED split_abc_line({line!r}) -> {actual!r}; expected {expected!r}", file=sys.stderr)
            return 1

    rows = [
        TripleRow("https://a.test/", "bob", "1"),
        TripleRow("https://a.test/", "bob", "1", file="other.txt", line=9),
        TripleRow("https://a.test/", "bob", "2"),
        TripleRow("https://a.test/", "alice", "1"),
    ]
    deduped = dedupe_and_sort_rows(rows)
    if len(deduped) != 3:
        print(f"FAILED dedupe length: {len(deduped)}", file=sys.stderr)
        return 1
    matcher = FieldMatcher(["ali"], "B", regex=False, ignore_case=True)
    if not matcher.matches(TripleRow("https://a.test/", "Alice", "x")):
        print("FAILED FieldMatcher B ignore-case", file=sys.stderr)
        return 1
    regex_matcher = FieldMatcher(["^Ali"], "B", regex=True, ignore_case=False)
    if not regex_matcher.matches(TripleRow("https://a.test/", "Alice", "x")):
        print("FAILED FieldMatcher B regex anchor", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory() as tmpdir:
        csv_path = Path(tmpdir) / "out.csv"
        txt_path = Path(tmpdir) / "out.txt"
        export_rows(csv_path, deduped, "csv")
        export_rows(txt_path, deduped, "txt")
        csv_lines = csv_path.read_text(encoding="utf-8-sig").splitlines()
        txt_lines = txt_path.read_text(encoding="utf-8").splitlines()
        if not csv_lines or csv_lines[0] != "A,B,C,file,line,source_line,matches":
            print("FAILED CSV export header", file=sys.stderr)
            return 1
        if len(txt_lines) != len(deduped):
            print("FAILED TXT export line count", file=sys.stderr)
            return 1
        if any(line.startswith("A:B:C") for line in txt_lines):
            print("FAILED TXT export should not include a header", file=sys.stderr)
            return 1
        if not all(line.count(":") >= 2 for line in txt_lines):
            print("FAILED TXT export A:B:C format", file=sys.stderr)
            return 1

        sample_file = Path(tmpdir) / "sample.txt"
        sample_file.write_text(
            "\n".join(
                [
                    "https://alpha.test/login:Alice:one",
                    "https://alpha.test/login:Alice:one",
                    "https://alpha.test/login:Bob:two",
                    "https://beta.test:8443/path:Carol:three:tail",
                    "not-a-triple",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        rg_path = shutil.which("rg") or "rg"
        args = argparse.Namespace(
            path=[str(sample_file)],
            regex=True,
            multiline=False,
            ignore_case=False,
            case_sensitive=True,
            smart_case=False,
            glob=[],
            exclude=[],
            all=False,
            hidden=False,
            no_ignore=False,
            text=False,
            follow=False,
            mmap=True,
            threads=0,
            max_filesize=None,
            max_columns=None,
            max_count_per_file=None,
            limit=None,
            progress_every=10000,
            quiet=True,
            debug=False,
            rg_bin=rg_path,
            field="B",
        )
        validate_common_args(args)
        result = search_abc_rows(args, ["^Ali"], progress=None)
        if len(result.rows) != 1:
            print(f"FAILED ABC search/dedupe expected 1 row, got {len(result.rows)}", file=sys.stderr)
            return 1
        if result.rows[0].a != "https://alpha.test/login" or result.rows[0].b != "Alice":
            print("FAILED ABC row content", file=sys.stderr)
            return 1

    print("self-test ok")
    return 0


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fast local folder content search with ripgrep, GUI, and A/B/C field mode."
    )
    parser.add_argument("--gui", action="store_true", help="Launch the merged Tkinter GUI.")
    parser.add_argument("--self-test", action="store_true", help="Run built-in parser/export tests and exit.")
    parser.add_argument("-p", "--path", nargs="+", default=[], help="Folder or file path to search.")
    parser.add_argument("-k", "--keywords", nargs="*", default=[], help="Keywords or patterns to search.")
    parser.add_argument("--keyword-file", action="append", default=[], help="File containing one keyword/pattern per line.")
    parser.add_argument("--keep-empty-keywords", action="store_true", help="Keep empty lines from keyword files.")
    parser.add_argument("-o", "--output", default=None, help="Output file path.")
    parser.add_argument("--format", choices=["txt", "csv", "jsonl", "md"], default=None, help="Output format.")
    parser.add_argument("--summary", default=None, help="Summary JSON path. Default: OUTPUT.summary.json")
    parser.add_argument("--no-summary", action="store_true", help="Do not write summary JSON.")
    parser.add_argument("--regex", action="store_true", help="Treat keywords as regex patterns. Default is fixed-string search.")
    parser.add_argument("--multiline", action="store_true", help="Enable ripgrep multiline mode when using --regex.")
    case_group = parser.add_mutually_exclusive_group()
    case_group.add_argument("--ignore-case", action="store_true", help="Case-insensitive search.")
    case_group.add_argument("--case-sensitive", action="store_true", help="Case-sensitive search.")
    case_group.add_argument("--smart-case", action="store_true", help="Smart-case search. This is the default for CLI.")
    parser.add_argument("--glob", action="append", default=[], help="Include glob. Can be repeated, e.g. --glob '*.py'.")
    parser.add_argument("--exclude", action="append", default=[], help="Exclude glob or folder. Can be repeated, e.g. --exclude '.git/**'.")
    parser.add_argument("--all", action="store_true", help="Search hidden, ignored, and binary-as-text files.")
    parser.add_argument("--hidden", action="store_true", help="Search hidden files and folders.")
    parser.add_argument("--no-ignore", action="store_true", help="Do not respect .gitignore/.ignore files.")
    parser.add_argument("--text", action="store_true", help="Search binary files as text.")
    parser.add_argument("--follow", action="store_true", help="Follow symbolic links.")
    parser.add_argument("--mmap", dest="mmap", action="store_true", default=True, help="Use memory maps where ripgrep can.")
    parser.add_argument("--no-mmap", dest="mmap", action="store_false", help="Disable memory maps.")
    parser.add_argument("--threads", type=int, default=0, help="Ripgrep thread count. 0 means auto.")
    parser.add_argument("--max-filesize", default=None, help="Skip files larger than this, e.g. 20M, 1G.")
    parser.add_argument("--max-columns", type=int, default=None, help="Skip very long lines after this many columns.")
    parser.add_argument("--max-count-per-file", type=int, default=None, help="Stop after N matches per file.")
    parser.add_argument("--limit", type=int, default=None, help="Stop after N unique written results.")
    parser.add_argument(
        "--dedupe",
        choices=["none", "line", "content", "file-content"],
        default="content",
        help="Normal-mode de-duplication mode. A/B/C mode always de-duplicates exact A/B/C triples.",
    )
    parser.add_argument(
        "--dedupe-store",
        choices=["memory", "sqlite"],
        default="memory",
        help="Store used for normal-mode de-duplication keys.",
    )
    parser.add_argument("--dedupe-db", default=None, help="SQLite de-duplication DB path when --dedupe-store sqlite.")
    parser.add_argument("--keep-dedupe-db", action="store_true", help="Keep auto-created SQLite de-duplication DB after the run.")
    parser.add_argument("--dedupe-trim", action="store_true", default=True, help="Trim content before de-duplication.")
    parser.add_argument("--no-dedupe-trim", dest="dedupe_trim", action="store_false", help="Do not trim content before de-duplication.")
    parser.add_argument("--dedupe-collapse-space", action="store_true", help="Collapse whitespace before de-duplication.")
    parser.add_argument("--dedupe-ignore-case", action="store_true", help="Ignore case when de-duplicating.")
    parser.add_argument("--flush-every", type=int, default=10000, help="SQLite commit interval.")
    parser.add_argument("--progress-every", type=int, default=10000, help="Print progress every N raw matches.")
    parser.add_argument("--quiet", action="store_true", help="Suppress progress output.")
    parser.add_argument("--debug", action="store_true", help="Print ripgrep command and forward stderr.")
    parser.add_argument("--rg-bin", default="rg", help="ripgrep executable name or path.")

    parser.add_argument("--abc", action="store_true", help="Enable A:B:C three-field parsing and table output.")
    parser.add_argument(
        "--field",
        choices=["ANY", "A", "B", "C", "any", "a", "b", "c"],
        default=None,
        help="A/B/C field to search. Passing --field also enables --abc.",
    )
    args = parser.parse_args(argv)
    if args.field is not None:
        args.abc = True
        args.field = args.field.upper()
    else:
        args.field = "ANY"
    if args.format is None:
        args.format = "csv" if args.abc else "jsonl"
    if args.output is None:
        if args.abc:
            ext = {"csv": "csv", "txt": "txt", "jsonl": "jsonl", "md": "md"}[args.format]
            args.output = f"rg_abc_results.{ext}"
        else:
            ext = {"csv": "csv", "txt": "txt", "jsonl": "jsonl", "md": "md"}[args.format]
            args.output = "rg_results.jsonl" if args.format == "jsonl" else f"rg_results.{ext}"
    return args


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_test()
    if args.gui:
        return run_gui()
    if args.abc:
        return run_abc_cli(args)
    return run_normal_cli(args)


if __name__ == "__main__":
    raise SystemExit(main())
