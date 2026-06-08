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
import json
import os
import queue
import re
import shlex
import shutil
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

VERSION = "4.0.0-ultra-abc"
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
ABC_TEXT_SEPARATOR = "\x1f"


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

    def is_duplicate(self, key: object) -> bool:
        if key in self._seen:
            return True
        self._seen.add(key)
        return False

    def close(self) -> None:
        return None



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


def make_dedupe_key(hit: Hit, args: argparse.Namespace) -> object:
    if args.dedupe == "none":
        return None
    content = normalize_for_dedupe(hit.content, args)
    # Avoid Path.resolve() per hit; rg already emits a stable path string for this run.
    file_path = hit.file or ""
    if args.dedupe == "content":
        return content
    if args.dedupe == "file-content":
        return (file_path, content)
    return (file_path, hit.line, content)

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


def regex_needs_field_scan(pattern: str) -> bool:
    """Return True when a regex is likely anchored to a field instead of a full line."""
    return pattern.startswith("^") or pattern.endswith("$") or "\\A" in pattern or "\\Z" in pattern or "\\z" in pattern


def abc_candidate_mode(args: argparse.Namespace, keywords: Sequence[str]) -> str:
    requested = getattr(args, "abc_candidate_mode", "auto")
    if requested in {"keyword", "colon"}:
        return requested
    if not args.regex:
        return "keyword"
    if any(regex_needs_field_scan(keyword) for keyword in keywords):
        return "colon"
    return "keyword"


def build_abc_candidate_rg_cmd(args: argparse.Namespace, pattern_file: Path, mode: str) -> List[str]:
    """Build the fastest safe ripgrep candidate scan for A/B/C mode.

    This uses ripgrep plain text output instead of --json to avoid JSON parsing
    overhead. A non-printing field separator keeps URL/content colons parse-safe.
    """
    cmd = [
        args.rg_bin,
        "--line-number",
        "--column",
        "--with-filename",
        "--no-heading",
        "--color",
        "never",
        "--field-match-separator",
        ABC_TEXT_SEPARATOR,
        "--threads",
        str(args.threads),
    ]
    add_common_rg_options(cmd, args)
    if mode == "colon":
        cmd.extend(["--fixed-strings", "--case-sensitive"])
    else:
        if args.regex:
            # A/B/C records are single-line; multiline makes plain output ambiguous.
            pass
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


def hit_from_rg_text_line(raw_line: str) -> Optional[Hit]:
    """Parse ripgrep text output: file<US>line<US>column<US>content."""
    text = raw_line.rstrip("\r\n")
    parts = text.split(ABC_TEXT_SEPARATOR, 3)
    if len(parts) != 4:
        return None
    file_path, line_text, column_text, content = parts
    try:
        line_number = int(line_text)
        column = int(column_text)
    except ValueError:
        return None
    return Hit(
        file=file_path,
        line=line_number,
        column=column,
        content=content,
        matches=[],
        submatches=[],
        absolute_offset=None,
    )


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
    _ = output_path
    if args.dedupe == "none":
        return None, None
    return MemoryDeduper(), None

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
    row_sink: Optional[Callable[[TripleRow], None]] = None,
    collect_rows: bool = True,
) -> ABCSearchResult:
    ignore_case = should_ignore_case_for_fields(args, keywords)
    try:
        matcher = FieldMatcher(keywords, args.field, args.regex, ignore_case)
    except re.error as exc:
        raise ValueError(f"invalid regex: {exc}") from exc

    mode = abc_candidate_mode(args, keywords)
    candidate_terms = [":"] if mode == "colon" else keywords
    candidate_pattern_file = create_pattern_file(candidate_terms)
    rows: List[TripleRow] = []
    seen_triples = set()
    raw_matches = 0
    parsed_triples = 0
    field_hits = 0
    written_rows = 0
    duplicates_removed = 0
    file_counts: Counter[str] = Counter()
    rg_summary: Dict[str, object] = {}
    return_code: Optional[int] = None
    limited = False
    started = time.time()
    cmd: List[str] = []

    def emit(message: str) -> None:
        if progress is not None:
            progress(message)

    try:
        cmd = build_abc_candidate_rg_cmd(args, candidate_pattern_file, mode)
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
            bufsize=1024 * 1024,
        )
        assert proc.stdout is not None
        for raw_line in proc.stdout:
            if cancel_event is not None and cancel_event.is_set():
                proc.terminate()
                raise RuntimeError("search cancelled")
            hit = hit_from_rg_text_line(raw_line)
            if hit is None:
                continue
            raw_matches += 1
            parsed = split_abc_line(hit.content)
            if parsed is None:
                if not args.quiet and raw_matches % args.progress_every == 0:
                    emit(
                        f"progress candidate={raw_matches:,} parsed={parsed_triples:,} "
                        f"matched={field_hits:,} unique={written_rows:,} dup={duplicates_removed:,}"
                    )
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
                field_hits += 1
                key = (row.a, row.b, row.c)
                if key in seen_triples:
                    duplicates_removed += 1
                else:
                    seen_triples.add(key)
                    row = replace(row, matches=tuple(matched_terms))
                    if row_sink is not None:
                        row_sink(row)
                    if collect_rows:
                        rows.append(row)
                    written_rows += 1
                    file_counts[row.file] += 1
                    if args.limit is not None and written_rows >= args.limit:
                        limited = True
                        proc.terminate()
                        break
            if not args.quiet and raw_matches % args.progress_every == 0:
                emit(
                    f"progress candidate={raw_matches:,} parsed={parsed_triples:,} "
                    f"matched={field_hits:,} unique={written_rows:,} dup={duplicates_removed:,}"
                )

        try:
            return_code = proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            return_code = proc.wait(timeout=5)
    finally:
        safe_unlink(candidate_pattern_file)

    elapsed = time.time() - started
    return ABCSearchResult(
        rows=rows,
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

def run_abc_cli_compat(args: argparse.Namespace) -> int:
    validate_common_args(args)
    keywords = load_keywords(args)
    if not keywords:
        raise SystemExit("no keywords or patterns provided; use -k or --keyword-file")

    output_path = Path(args.output).resolve()
    summary_path = None
    if not args.no_summary:
        summary_path = Path(args.summary).resolve() if args.summary else output_path.with_suffix(output_path.suffix + ".summary.json")

    mode = abc_candidate_mode(args, keywords)
    if not args.quiet:
        print(f"rg-search v{VERSION} A/B/C mode")
        print(
            f"keywords={len(keywords):,} field={args.field} mode={'regex' if args.regex else 'fixed'} "
            f"dedupe=A->B->C memory-set candidate={mode}"
        )
        print(f"output={output_path}")
        if mode == "keyword":
            print("A/B/C mode uses ripgrep keyword prefilter plus non-JSON streaming, then field-accurate parsing/filtering.")
        else:
            print("A/B/C regex anchors detected; scanning ':' candidates for field-accurate regex matching.")

    with TripleWriter(output_path, args.format) as writer:
        result = search_abc_rows(
            args,
            keywords,
            progress=(lambda msg: print(msg, flush=True)) if not args.quiet else None,
            row_sink=writer.write,
            collect_rows=False,
        )

    summary = {
        "version": VERSION,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "mode": "abc",
        "path": args.path,
        "output": str(output_path),
        "format": args.format,
        "keywords_count": len(keywords),
        "field": args.field,
        "candidate_mode": mode,
        "search_mode": "regex" if args.regex else "fixed",
        "dedupe": "A->B->C exact triple in memory",
        "raw_candidate_lines": result.raw_matches,
        "parsed_triples": result.parsed_triples,
        "field_hits_before_dedupe": result.field_hits,
        "written_results": result.field_hits - result.duplicates_removed,
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
        written = result.field_hits - result.duplicates_removed
        print(
            f"done candidate={result.raw_matches:,} parsed={result.parsed_triples:,} "
            f"matched={result.field_hits:,} written={written:,} "
            f"dup={result.duplicates_removed:,} elapsed={result.elapsed_seconds:.2f}s"
        )
        if summary_path is not None:
            print(f"summary={summary_path}")
    if result.limited:
        return 0
    if result.rg_return_code in (0, 1, None):
        return 0
    return int(result.rg_return_code)


ABC_FAST_COLUMNS = ["A", "B", "C"]
ABC_FULL_COLUMNS = ["A", "B", "C", "file", "line", "source_line", "matches"]


def split_abc_line_simple(line: str) -> Optional[Tuple[str, str, str]]:
    """Fastest parser for strict A:B:C lines where A never contains ':'."""
    i = line.find(":")
    if i <= 0:
        return None
    j = line.find(":", i + 1)
    if j <= i + 1:
        return None
    a = line[:i].strip()
    b = line[i + 1 : j].strip()
    if not a or not b:
        return None
    return a, b, line[j + 1 :].strip()


def split_abc_line_url_fast(line: str) -> Optional[Tuple[str, str, str]]:
    """Optimized URL-aware A:B:C parser.

    Fast path for URL:B:C records:
    - If A contains a path/query/fragment, the separator is the first ':' after it.
    - If A is only an authority, skip one numeric port before taking the separator.
    - Falls back to simple split for non-URL records.
    """
    if not line:
        return None

    scheme_pos = line.find("://")
    if scheme_pos > 0:
        scan_start = scheme_pos + 3

        pathish = -1
        slash = line.find("/", scan_start)
        qmark = line.find("?", scan_start)
        hashmark = line.find("#", scan_start)
        if slash != -1:
            pathish = slash
        if qmark != -1 and (pathish == -1 or qmark < pathish):
            pathish = qmark
        if hashmark != -1 and (pathish == -1 or hashmark < pathish):
            pathish = hashmark

        if pathish != -1:
            sep = line.find(":", pathish)
            if sep > 0:
                next_sep = line.find(":", sep + 1)
                if next_sep > sep + 1:
                    a = line[:sep].strip()
                    b = line[sep + 1 : next_sep].strip()
                    if a and b:
                        return a, b, line[next_sep + 1 :].strip()

        # URL without path/query/fragment, or malformed path case.
        sep = line.find(":", scan_start)
        if sep > 0:
            next_sep = line.find(":", sep + 1)
            if next_sep > sep + 1 and line[sep + 1 : next_sep].isdigit():
                sep = next_sep
                next_sep = line.find(":", sep + 1)
            if next_sep > sep + 1:
                a = line[:sep].strip()
                b = line[sep + 1 : next_sep].strip()
                if a and b:
                    return a, b, line[next_sep + 1 :].strip()

    return split_abc_line_simple(line)


def split_abc_line_urlpath_fast(line: str) -> Optional[Tuple[str, str, str]]:
    """Very fast parser for the common URL/path:B:C shape.

    It tries only the path slash after scheme:// first, then falls back to the
    more general URL-aware parser for URL records without a path or with ports.
    """
    scheme_pos = line.find("://")
    if scheme_pos > 0:
        slash = line.find("/", scheme_pos + 3)
        if slash != -1:
            sep = line.find(":", slash)
            if sep > 0:
                next_sep = line.find(":", sep + 1)
                if next_sep > sep + 1:
                    a = line[:sep].strip()
                    b = line[sep + 1 : next_sep].strip()
                    if a and b:
                        return a, b, line[next_sep + 1 :].strip()
    return split_abc_line_url_fast(line)


def split_abc_line_fast(line: str, parse_mode: str) -> Optional[Tuple[str, str, str]]:
    if parse_mode == "simple":
        return split_abc_line_simple(line)
    if parse_mode == "urlpath":
        return split_abc_line_urlpath_fast(line)
    return split_abc_line_url_fast(line)


def build_abc_ultra_rg_cmd(
    args: argparse.Namespace,
    pattern_file: Path,
    mode: str,
    with_meta: bool,
) -> List[str]:
    """Build the fastest A/B/C candidate scan.

    with_meta=False emits only the matched source line, like FastScan.py, avoiding
    filename/line parsing overhead. with_meta=True still avoids JSON and dataclass
    allocations while preserving file and line columns.
    """
    cmd = [args.rg_bin, "--no-heading", "--color", "never", "--threads", str(args.threads)]
    if with_meta:
        cmd.extend([
            "--line-number",
            "--column",
            "--with-filename",
            "--field-match-separator",
            ABC_TEXT_SEPARATOR,
        ])
    else:
        cmd.extend(["--no-line-number", "--no-filename"])

    add_common_rg_options(cmd, args)
    if mode == "colon":
        cmd.extend(["--fixed-strings", "--case-sensitive"])
    else:
        if not args.regex:
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


def parse_rg_ultra_line(raw_line: str, with_meta: bool) -> Optional[Tuple[str, int, int, str]]:
    """Return file,line,column,content from rg plain output."""
    if raw_line.endswith("\n"):
        raw_line = raw_line[:-1]
    if raw_line.endswith("\r"):
        raw_line = raw_line[:-1]
    if not with_meta:
        return "", 0, 1, raw_line
    parts = raw_line.split(ABC_TEXT_SEPARATOR, 3)
    if len(parts) != 4:
        return None
    file_path, line_text, column_text, content = parts
    try:
        return file_path, int(line_text), int(column_text), content
    except ValueError:
        return None


def make_fast_field_matcher(
    keywords: Sequence[str],
    field: str,
    regex: bool,
    ignore_case: bool,
    keep_matches: bool,
    candidate_mode: str,
) -> Callable[[str, str, str], Optional[str]]:
    """Create a low-allocation matcher returning None on miss, match text on hit."""
    field = field.upper()
    if field not in {"ANY", "A", "B", "C"}:
        raise ValueError("--field must be one of ANY, A, B, C")

    # When rg already prefiltered by the same line-level keyword/regex and the
    # user selected ANY, accepting candidates is exact and fastest.
    if field == "ANY" and candidate_mode == "keyword" and not keep_matches:
        return lambda a, b, c: ""

    def choose(a: str, b: str, c: str) -> Tuple[str, ...]:
        if field == "A":
            return (a,)
        if field == "B":
            return (b,)
        if field == "C":
            return (c,)
        return (a, b, c)

    if regex:
        flags = re.IGNORECASE if ignore_case else 0
        patterns = [(kw, re.compile(kw, flags)) for kw in keywords]

        if keep_matches:
            def regex_keep(a: str, b: str, c: str) -> Optional[str]:
                values = choose(a, b, c)
                found: List[str] = []
                for label, pattern in patterns:
                    for value in values:
                        if pattern.search(value):
                            found.append(label)
                            break
                return ";".join(found) if found else None
            return regex_keep

        def regex_bool(a: str, b: str, c: str) -> Optional[str]:
            values = choose(a, b, c)
            for _label, pattern in patterns:
                for value in values:
                    if pattern.search(value):
                        return ""
            return None
        return regex_bool

    # Fixed-string matching.
    if ignore_case:
        needles = [kw.casefold() for kw in keywords]

        if len(needles) == 1:
            needle = needles[0]
            label = keywords[0]
            if field == "A":
                return lambda a, b, c: (label if keep_matches else "") if needle in a.casefold() else None
            if field == "B":
                return lambda a, b, c: (label if keep_matches else "") if needle in b.casefold() else None
            if field == "C":
                return lambda a, b, c: (label if keep_matches else "") if needle in c.casefold() else None
            return lambda a, b, c: (label if keep_matches else "") if (
                needle in a.casefold() or needle in b.casefold() or needle in c.casefold()
            ) else None

        def fixed_icase_multi(a: str, b: str, c: str) -> Optional[str]:
            if field == "A":
                values = (a.casefold(),)
            elif field == "B":
                values = (b.casefold(),)
            elif field == "C":
                values = (c.casefold(),)
            else:
                values = (a.casefold(), b.casefold(), c.casefold())
            if keep_matches:
                found = []
                for label, needle in zip(keywords, needles):
                    if any(needle in value for value in values):
                        found.append(label)
                return ";".join(found) if found else None
            for needle in needles:
                if any(needle in value for value in values):
                    return ""
            return None
        return fixed_icase_multi

    if len(keywords) == 1:
        needle = keywords[0]
        if field == "A":
            return lambda a, b, c: (needle if keep_matches else "") if needle in a else None
        if field == "B":
            return lambda a, b, c: (needle if keep_matches else "") if needle in b else None
        if field == "C":
            return lambda a, b, c: (needle if keep_matches else "") if needle in c else None
        return lambda a, b, c: (needle if keep_matches else "") if (needle in a or needle in b or needle in c) else None

    def fixed_multi(a: str, b: str, c: str) -> Optional[str]:
        if field == "A":
            values = (a,)
        elif field == "B":
            values = (b,)
        elif field == "C":
            values = (c,)
        else:
            values = (a, b, c)
        if keep_matches:
            found = []
            for needle in keywords:
                if any(needle in value for value in values):
                    found.append(needle)
            return ";".join(found) if found else None
        for needle in keywords:
            if any(needle in value for value in values):
                return ""
        return None
    return fixed_multi


class FastABCWriter:
    """Low-overhead writer for CLI A/B/C ultra mode."""

    def __init__(self, output: Path, fmt: str, columns: str) -> None:
        self.output = output
        self.format = fmt
        self.columns = columns
        self.tmp_output = output.with_name(output.name + ".tmp")
        self.fp = None
        self.csv_writer = None

    def __enter__(self) -> "FastABCWriter":
        self.output.parent.mkdir(parents=True, exist_ok=True)
        if self.format == "csv":
            self.fp = open(self.tmp_output, "w", encoding="utf-8-sig", newline="", buffering=1024 * 1024)
            self.csv_writer = csv.writer(self.fp)
            self.csv_writer.writerow(ABC_FAST_COLUMNS if self.columns == "abc" else ABC_FULL_COLUMNS)
        else:
            self.fp = open(self.tmp_output, "w", encoding="utf-8", buffering=1024 * 1024)
            if self.format == "md":
                if self.columns == "abc":
                    self.fp.write("| A | B | C |\n|---|---|---|\n")
                else:
                    self.fp.write("| A | B | C | file | line | source_line | matches |\n")
                    self.fp.write("|---|---|---|---|---:|---|---|\n")
        return self

    def write(
        self,
        a: str,
        b: str,
        c: str,
        file_path: str = "",
        line_number: int = 0,
        source_line: str = "",
        matches: str = "",
    ) -> None:
        if self.fp is None:
            raise RuntimeError("writer is not open")
        if self.format == "csv":
            if self.csv_writer is None:
                raise RuntimeError("csv writer is not open")
            if self.columns == "abc":
                self.csv_writer.writerow((a, b, c))
            else:
                self.csv_writer.writerow((a, b, c, file_path, line_number, source_line, matches))
            return
        if self.format == "txt":
            self.fp.write(f"{sanitize_txt_part(a)}:{sanitize_txt_part(b)}:{sanitize_txt_part(c)}\n")
            return
        if self.format == "jsonl":
            if self.columns == "abc":
                obj = {"A": a, "B": b, "C": c}
            else:
                obj = {
                    "A": a,
                    "B": b,
                    "C": c,
                    "file": file_path,
                    "line": line_number,
                    "source_line": source_line,
                    "matches": matches.split(";") if matches else [],
                }
            self.fp.write(json.dumps(obj, ensure_ascii=False) + "\n")
            return
        if self.format == "md":
            if self.columns == "abc":
                self.fp.write(f"| {md_escape(a)} | {md_escape(b)} | {md_escape(c)} |\n")
            else:
                self.fp.write(
                    f"| {md_escape(a)} | {md_escape(b)} | {md_escape(c)} | "
                    f"{md_escape(file_path)} | {line_number} | {md_escape(source_line)} | {md_escape(matches)} |\n"
                )
            return
        self.fp.write(f"{sanitize_txt_part(a)}:{sanitize_txt_part(b)}:{sanitize_txt_part(c)}\n")

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.fp is not None:
            self.fp.close()
        if exc_type is None:
            os.replace(self.tmp_output, self.output)
        else:
            safe_unlink(self.tmp_output)


def run_abc_ultra_cli(args: argparse.Namespace) -> int:
    validate_common_args(args)
    keywords = load_keywords(args)
    if not keywords:
        raise SystemExit("no keywords or patterns provided; use -k or --keyword-file")

    output_path = Path(args.output).resolve()
    summary_path = None
    if not args.no_summary:
        summary_path = Path(args.summary).resolve() if args.summary else output_path.with_suffix(output_path.suffix + ".summary.json")

    mode = abc_candidate_mode(args, keywords)
    candidate_terms = [":"] if mode == "colon" else keywords
    candidate_pattern_file = create_pattern_file(candidate_terms)
    ignore_case = should_ignore_case_for_fields(args, keywords)
    keep_matches = bool(getattr(args, "abc_keep_matches", False))
    with_meta = getattr(args, "abc_columns", "abc") == "full"
    parse_mode = getattr(args, "abc_parse", "url")
    dedupe_enabled = args.dedupe != "none"

    try:
        matcher = make_fast_field_matcher(
            keywords,
            args.field,
            args.regex,
            ignore_case,
            keep_matches,
            mode,
        )
    except re.error as exc:
        safe_unlink(candidate_pattern_file)
        raise SystemExit(f"invalid regex: {exc}") from exc

    raw_matches = 0
    parsed_triples = 0
    field_hits = 0
    written = 0
    duplicates_removed = 0
    file_counts: Counter[str] = Counter()
    limited = False
    return_code: Optional[int] = None
    started = time.time()
    cmd: List[str] = []
    seen_triples = set() if dedupe_enabled else None

    try:
        cmd = build_abc_ultra_rg_cmd(args, candidate_pattern_file, mode, with_meta=with_meta)
        if not args.quiet:
            print(f"rg-search v{VERSION} A/B/C ultra mode")
            print(
                f"keywords={len(keywords):,} field={args.field} mode={'regex' if args.regex else 'fixed'} "
                f"candidate={mode} parse={parse_mode} columns={args.abc_columns} dedupe={'on' if dedupe_enabled else 'off'}"
            )
            print(f"output={output_path}")
            print("ultra path: rg plain stream -> parse field -> match -> set dedupe -> write, no JSON/dataclass/sort/SQLite")
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
            bufsize=1024 * 1024 * 4,
        )
        assert proc.stdout is not None
        with FastABCWriter(output_path, args.format, getattr(args, "abc_columns", "abc")) as writer:
            for raw_line in proc.stdout:
                rec = parse_rg_ultra_line(raw_line, with_meta)
                if rec is None:
                    continue
                file_path, line_number, _column, content = rec
                raw_matches += 1
                parsed = split_abc_line_fast(content, parse_mode)
                if parsed is None:
                    if not args.quiet and raw_matches % args.progress_every == 0:
                        print(
                            f"progress candidate={raw_matches:,} parsed={parsed_triples:,} "
                            f"matched={field_hits:,} unique={written:,} dup={duplicates_removed:,}",
                            flush=True,
                        )
                    continue
                parsed_triples += 1
                a, b, c = parsed
                matches = matcher(a, b, c)
                if matches is None:
                    if not args.quiet and raw_matches % args.progress_every == 0:
                        print(
                            f"progress candidate={raw_matches:,} parsed={parsed_triples:,} "
                            f"matched={field_hits:,} unique={written:,} dup={duplicates_removed:,}",
                            flush=True,
                        )
                    continue
                field_hits += 1
                if seen_triples is not None:
                    key = (a, b, c)
                    if key in seen_triples:
                        duplicates_removed += 1
                        continue
                    seen_triples.add(key)
                writer.write(a, b, c, file_path, line_number, content if with_meta else "", matches)
                written += 1
                if with_meta and file_path:
                    file_counts[file_path] += 1
                if args.limit is not None and written >= args.limit:
                    limited = True
                    proc.terminate()
                    break
                if not args.quiet and raw_matches % args.progress_every == 0:
                    print(
                        f"progress candidate={raw_matches:,} parsed={parsed_triples:,} "
                        f"matched={field_hits:,} unique={written:,} dup={duplicates_removed:,}",
                        flush=True,
                    )

        try:
            return_code = proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            return_code = proc.wait(timeout=5)
    finally:
        safe_unlink(candidate_pattern_file)

    elapsed = time.time() - started
    summary = {
        "version": VERSION,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "mode": "abc-ultra",
        "path": args.path,
        "output": str(output_path),
        "format": args.format,
        "columns": getattr(args, "abc_columns", "abc"),
        "keywords_count": len(keywords),
        "field": args.field,
        "candidate_mode": mode,
        "parse_mode": parse_mode,
        "search_mode": "regex" if args.regex else "fixed",
        "dedupe": "A->B->C exact triple in memory" if dedupe_enabled else "none",
        "raw_candidate_lines": raw_matches,
        "parsed_triples": parsed_triples,
        "field_hits_before_dedupe": field_hits,
        "written_results": written,
        "duplicates_removed": duplicates_removed,
        "files_with_written_hits": len(file_counts),
        "top_files": [{"file": file, "hits": count} for file, count in file_counts.most_common(20)],
        "elapsed_seconds": round(elapsed, 3),
        "raw_candidates_per_second": round(raw_matches / elapsed, 2) if elapsed > 0 else raw_matches,
        "written_per_second": round(written / elapsed, 2) if elapsed > 0 else written,
        "limited": limited,
        "rg_return_code": return_code,
        "command": shlex.join(cmd) if cmd else "",
    }
    if summary_path is not None:
        write_summary(summary_path, summary)
    if not args.quiet:
        print(
            f"done candidate={raw_matches:,} parsed={parsed_triples:,} matched={field_hits:,} "
            f"written={written:,} dup={duplicates_removed:,} elapsed={elapsed:.2f}s"
        )
        if summary_path is not None:
            print(f"summary={summary_path}")
    if limited:
        return 0
    if return_code in (0, 1, None):
        return 0
    return int(return_code)


def run_abc_cli(args: argparse.Namespace) -> int:
    if getattr(args, "abc_ultra", True):
        return run_abc_ultra_cli(args)
    return run_abc_cli_compat(args)

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
        choices=["memory"],
        default="memory",
        help="De-duplication store. Only memory is supported for maximum speed.",
    )
    parser.add_argument("--dedupe-trim", action="store_true", default=True, help="Trim content before de-duplication.")
    parser.add_argument("--no-dedupe-trim", dest="dedupe_trim", action="store_false", help="Do not trim content before de-duplication.")
    parser.add_argument("--dedupe-collapse-space", action="store_true", help="Collapse whitespace before de-duplication.")
    parser.add_argument("--dedupe-ignore-case", action="store_true", help="Ignore case when de-duplicating.")
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
    parser.add_argument(
        "--abc-candidate-mode",
        choices=["auto", "keyword", "colon"],
        default="auto",
        help="A/B/C candidate scan mode. auto uses keyword prefilter for speed and colon scan only when needed.",
    )
    parser.add_argument(
        "--abc-ultra",
        dest="abc_ultra",
        action="store_true",
        default=True,
        help="Use the fastest A/B/C CLI path: plain rg stream, inline parse/match/dedupe/write. Default: on.",
    )
    parser.add_argument(
        "--no-abc-ultra",
        dest="abc_ultra",
        action="store_false",
        help="Use the compatibility A/B/C path that keeps older full metadata behavior.",
    )
    parser.add_argument(
        "--abc-columns",
        choices=["abc", "full"],
        default="abc",
        help="A/B/C ultra output columns. 'abc' is fastest; 'full' also emits file,line,source_line,matches.",
    )
    parser.add_argument(
        "--abc-keep-matches",
        action="store_true",
        help="Fill the matches column in --abc-columns full. Leaving it off is faster.",
    )
    parser.add_argument(
        "--abc-parse",
        choices=["urlpath", "url", "simple"],
        default="urlpath",
        help="A/B/C parser. 'urlpath' is fastest for URL/path:B:C; 'url' is more general URL-aware; 'simple' uses split(':', 2) when A never contains ':'.",
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
    raw_argv = list(argv if argv is not None else sys.argv[1:])
    args = parse_args(raw_argv)

    if args.self_test:
        return run_self_test()

    # 默认无参数时打开 GUI：
    #   python3 rgs.py
    # 有参数时仍然走 CLI：
    #   python3 rgs.py -p ./data -k test --field B
    if args.gui or len(raw_argv) == 0:
        return run_gui()

    if args.abc:
        return run_abc_cli(args)

    return run_normal_cli(args)


if __name__ == "__main__":
    raise SystemExit(main())
