#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
rgs.py

A high-speed folder content search tool powered by ripgrep.

Highlights:
- Very fast recursive folder search through ripgrep.
- Multiple keywords or regex patterns.
- Large keyword lists via a temporary pattern file.
- Streamed output: txt, csv, jsonl, markdown.
- Result de-duplication: by content, by file+content, by file+line+content, or off.
- Memory or SQLite de-dupe store for very large result sets.
- Progress logging, limits, file glob include/exclude filters, and summary report.

Examples:
  python3 rgs.py -p /data -k password token secret -o result.jsonl --format jsonl
  python3 rgs.py -p /data -k OpenWrt --glob '*.c' --glob '*.h' --dedupe content
  python3 rgs.py -p /data --keyword-file keywords.txt -o result.csv --format csv --dedupe-store sqlite
  python3 rgs.py -p /data -k api_key --all --exclude '.git/**' --exclude 'node_modules/**'
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
import os
import shlex
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from collections import Counter
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

VERSION = "2.0.0"


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
            try:
                self.tmp_output.unlink(missing_ok=True)
            except TypeError:
                if self.tmp_output.exists():
                    self.tmp_output.unlink()


def md_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ").replace("\r", " ")


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
    result = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


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
    fp = tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, prefix="rg_patterns_", suffix=".txt")
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
    has_glob = any(ch in item for ch in "*?[{")
    if not has_glob and not item.endswith("/**"):
        candidates.append(item.rstrip("/") + "/**")

    expanded: List[str] = []
    for candidate in candidates:
        expanded.append(candidate)
        if not candidate.startswith("**/") and not candidate.startswith("/"):
            expanded.append("**/" + candidate)
    return unique_keep_order(expanded)


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

    if args.mmap:
        cmd.append("--mmap")
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
        cmd.extend(["--max-filesize", args.max_filesize])
    if args.max_columns:
        cmd.extend(["--max-columns", str(args.max_columns)])
    if args.max_count_per_file:
        cmd.extend(["--max-count", str(args.max_count_per_file)])

    for item in args.glob or []:
        cmd.extend(["--glob", item])
    for item in args.exclude or []:
        for expanded in expand_exclude_glob(item):
            cmd.extend(["--glob", f"!{expanded}"])

    cmd.extend(["--file", str(pattern_file)])
    cmd.extend(args.path)
    return cmd


def validate_args(args: argparse.Namespace) -> None:
    args.rg_bin = shutil.which(args.rg_bin) or args.rg_bin
    if shutil.which(args.rg_bin) is None and not Path(args.rg_bin).exists():
        raise SystemExit("ripgrep executable not found. Install rg or pass --rg-bin /path/to/rg")

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


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Ultra-fast folder content search with streamed output and de-duplication."
    )
    parser.add_argument("-p", "--path", nargs="+", required=True, help="Folder or file path to search.")
    parser.add_argument("-k", "--keywords", nargs="*", default=[], help="Keywords or patterns to search.")
    parser.add_argument("--keyword-file", action="append", default=[], help="File containing one keyword/pattern per line.")
    parser.add_argument("--keep-empty-keywords", action="store_true", help="Keep empty lines from keyword files.")

    parser.add_argument("-o", "--output", default="rg_results.jsonl", help="Output file path.")
    parser.add_argument("--format", choices=["txt", "csv", "jsonl", "md"], default="jsonl", help="Output format.")
    parser.add_argument("--summary", default=None, help="Summary JSON path. Default: OUTPUT.summary.json")
    parser.add_argument("--no-summary", action="store_true", help="Do not write summary JSON.")

    parser.add_argument("--regex", action="store_true", help="Treat keywords as regex patterns. Default is fixed-string search.")
    parser.add_argument("--multiline", action="store_true", help="Enable ripgrep multiline mode when using --regex.")

    case_group = parser.add_mutually_exclusive_group()
    case_group.add_argument("--ignore-case", action="store_true", help="Case-insensitive search.")
    case_group.add_argument("--case-sensitive", action="store_true", help="Case-sensitive search.")
    case_group.add_argument("--smart-case", action="store_true", help="Smart-case search. This is the default.")

    parser.add_argument("--glob", action="append", default=[], help="Include glob. Can be repeated, e.g. --glob '*.py'.")
    parser.add_argument("--exclude", action="append", default=[], help="Exclude glob. Can be repeated, e.g. --exclude '.git/**'.")
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
        help="De-duplication mode. Default removes repeated identical result content across files.",
    )
    parser.add_argument(
        "--dedupe-store",
        choices=["memory", "sqlite"],
        default="memory",
        help="Store used for de-duplication keys. Use sqlite for very large result sets.",
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

    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    validate_args(args)

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
            print(f"rg-search-ultra v{VERSION}")
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
        try:
            pattern_file.unlink(missing_ok=True)
        except TypeError:
            if pattern_file.exists():
                pattern_file.unlink()
        if dedupe_db_path and not args.keep_dedupe_db and not args.dedupe_db:
            for candidate in [dedupe_db_path, Path(str(dedupe_db_path) + "-wal"), Path(str(dedupe_db_path) + "-shm")]:
                try:
                    candidate.unlink(missing_ok=True)
                except TypeError:
                    if candidate.exists():
                        candidate.unlink()

    elapsed = time.time() - started
    summary = {
        "version": VERSION,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
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


if __name__ == "__main__":
    sys.exit(main())
