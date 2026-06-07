#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rgs_gui.py

A non-destructive Tkinter GUI wrapper for rg-search/rgs.py.

It keeps the original CLI script unchanged and adds an interactive workflow for
local security testing / authorized data review of three-part lines such as:

    A:B:C

For URL-style A fields, the parser understands the scheme separator in
"https://" and keeps any extra ':' characters after the B field inside C.

Usage:
    python3 rgs_gui.py

Place this file beside rgs.py, or choose rgs.py from the GUI.
"""
from __future__ import annotations

import csv
import json
import os
import queue
import re
import shlex
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, List, Optional, Sequence, Tuple

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

APP_TITLE = "rg-search GUI - A/B/C Field Search"
APP_VERSION = "1.1.0"
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


@dataclass(frozen=True)
class TripleRow:
    """One parsed A/B/C hit, with source location kept for auditability."""

    a: str
    b: str
    c: str
    file: str = ""
    line: int = 0
    source_line: str = ""


@dataclass
class SearchConfig:
    rgs_path: Path
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


def unique_keep_order(values: Iterable[str]) -> List[str]:
    seen = set()
    result: List[str] = []
    for raw in values:
        value = raw.strip()
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def parse_multiline_values(text: str) -> List[str]:
    """Parse one-value-per-line text, ignoring blank lines."""
    return unique_keep_order(line for line in text.splitlines())


def parse_keyword_values(text: str) -> List[str]:
    """
    Parse keywords as one per line.

    A single-line value is kept as one keyword instead of splitting on spaces,
    because security test strings can legitimately contain spaces.
    """
    return parse_multiline_values(text)


def find_url_aware_separator(text: str) -> Optional[int]:
    """
    Find the A/B separator for URL-like A fields.

    The usual credential-audit format is URL:USER:PASS. A plain split(':', 2)
    would break at 'https://'. This function skips the scheme separator and a
    likely numeric port in the authority section, then returns the first ':' that
    still leaves a non-empty B field and a C field after it.
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

        # Skip a likely URL port before the path, e.g. https://host:8443/path:u:p
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
    - URL-like A fields keep the scheme separator, e.g. 'https://'.
    - B is delimited by the first ':' after A.
    - Any further ':' characters belong to C, so C may contain ':'.
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
        self.field = field
        self.regex = regex
        self.ignore_case = ignore_case
        self._regexes: List[re.Pattern[str]] = []
        if regex:
            flags = re.IGNORECASE if ignore_case else 0
            for keyword in self.keywords:
                self._regexes.append(re.compile(keyword, flags))
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

    def matches(self, row: TripleRow) -> bool:
        values = self._values_for_row(row)
        if self.regex:
            return any(pattern.search(value) for pattern in self._regexes for value in values)
        if self.ignore_case:
            haystacks = [value.casefold() for value in values]
        else:
            haystacks = values
        return any(needle in haystack for needle in self._needles for haystack in haystacks)


def dedupe_and_sort_rows(rows: Iterable[TripleRow]) -> List[TripleRow]:
    """
    De-duplicate after field filtering using A -> B -> C comparison.

    Rows are sorted by A, then B, then C. Only identical (A, B, C) triples are
    removed; if A is the same but B or C differs, the row is retained.
    """
    sorted_rows = sorted(
        rows,
        key=lambda row: (row.a.casefold(), row.b.casefold(), row.c.casefold(), row.file, row.line),
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


def row_from_jsonl_record(record: dict) -> Optional[TripleRow]:
    content = str(record.get("content", ""))
    parsed = split_abc_line(content)
    if parsed is None:
        return None
    a, b, c = parsed
    try:
        line_no = int(record.get("line", 0) or 0)
    except (TypeError, ValueError):
        line_no = 0
    return TripleRow(
        a=a,
        b=b,
        c=c,
        file=str(record.get("file", "")),
        line=line_no,
        source_line=content,
    )


def build_rgs_command(config: SearchConfig, keyword_file: Path, jsonl_output: Path) -> List[str]:
    cmd = [
        sys.executable,
        str(config.rgs_path),
        "-p",
        *config.paths,
        "--keyword-file",
        str(keyword_file),
        "-o",
        str(jsonl_output),
        "--format",
        "jsonl",
        "--dedupe",
        "none",
        "--quiet",
        "--rg-bin",
        config.rg_bin or "rg",
    ]

    if config.regex:
        cmd.append("--regex")
    if config.ignore_case:
        cmd.append("--ignore-case")
    else:
        cmd.append("--case-sensitive")
    if config.all_files:
        cmd.append("--all")

    for pattern in config.include_globs:
        cmd.extend(["--glob", pattern])
    for pattern in config.exclude_globs:
        cmd.extend(["--exclude", pattern])

    if config.max_filesize:
        cmd.extend(["--max-filesize", config.max_filesize])
    if config.max_columns:
        cmd.extend(["--max-columns", config.max_columns])
    if config.max_count_per_file:
        cmd.extend(["--max-count-per-file", config.max_count_per_file])

    return cmd


def run_search(
    config: SearchConfig,
    progress: Callable[[str], None],
    cancel_event: threading.Event,
) -> List[TripleRow]:
    if not config.rgs_path.exists():
        raise FileNotFoundError(f"找不到 rgs.py: {config.rgs_path}")
    if not config.paths:
        raise ValueError("至少需要选择一个要检索的文件或目录。")
    if not config.keywords:
        raise ValueError("至少需要输入一个关键词。")

    # Compile early to surface regex errors before starting ripgrep.
    matcher = FieldMatcher(config.keywords, config.field, config.regex, config.ignore_case)

    tmp_jsonl = tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, suffix=".jsonl")
    tmp_keywords = tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, suffix=".txt")
    tmp_jsonl_path = Path(tmp_jsonl.name)
    tmp_keyword_path = Path(tmp_keywords.name)
    tmp_jsonl.close()
    try:
        for keyword in config.keywords:
            tmp_keywords.write(keyword.replace("\r", " ").replace("\n", " ") + "\n")
    finally:
        tmp_keywords.close()

    cmd = build_rgs_command(config, tmp_keyword_path, tmp_jsonl_path)
    progress("开始调用 rgs.py 进行本地检索。")
    progress("字段过滤将在 rgs.py 产出 JSONL 后执行，确保只保留指定 A/B/C 字段命中的行。")

    proc: Optional[subprocess.Popen[str]] = None
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        while proc.poll() is None:
            if cancel_event.is_set():
                progress("收到取消请求，正在终止检索进程。")
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                raise RuntimeError("检索已取消。")
            time.sleep(0.1)
        stdout, stderr = proc.communicate(timeout=5)
        if stdout.strip():
            progress(stdout.strip())
        if proc.returncode not in (0, 1, None):
            stderr_text = stderr.strip() or f"rgs.py return code: {proc.returncode}"
            raise RuntimeError(stderr_text)

        progress("开始解析三段式内容并执行字段过滤。")
        raw_hits = 0
        parsed_hits = 0
        field_hits: List[TripleRow] = []
        with open(tmp_jsonl_path, "r", encoding="utf-8", errors="replace") as fp:
            for raw_line in fp:
                if cancel_event.is_set():
                    raise RuntimeError("检索已取消。")
                raw_hits += 1
                try:
                    record = json.loads(raw_line)
                except json.JSONDecodeError:
                    continue
                row = row_from_jsonl_record(record)
                if row is None:
                    continue
                parsed_hits += 1
                if matcher.matches(row):
                    field_hits.append(row)

        progress(f"rgs.py 原始命中 {raw_hits:,} 行；可解析三段式 {parsed_hits:,} 行；字段过滤后 {len(field_hits):,} 行。")
        deduped = dedupe_and_sort_rows(field_hits)
        removed = len(field_hits) - len(deduped)
        progress(f"按 A -> B -> C 去重完成，移除 {removed:,} 条重复三段式记录。")

        if config.output_limit > 0 and len(deduped) > config.output_limit:
            progress(f"结果超过显示上限 {config.output_limit:,}，仅显示前 {config.output_limit:,} 条。")
            deduped = deduped[: config.output_limit]
        return deduped
    finally:
        for candidate in (tmp_jsonl_path, tmp_keyword_path):
            try:
                candidate.unlink(missing_ok=True)
            except TypeError:
                if candidate.exists():
                    candidate.unlink()


EXPORT_COLUMNS = ["A", "B", "C", "file", "line", "source_line"]


def row_to_export_dict(row: TripleRow) -> dict:
    return {
        "A": row.a,
        "B": row.b,
        "C": row.c,
        "file": row.file,
        "line": row.line,
        "source_line": row.source_line,
    }


def export_rows_to_csv(path: Path, rows: Sequence[TripleRow]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8-sig", newline="") as fp:
        writer = csv.DictWriter(fp, fieldnames=EXPORT_COLUMNS)
        writer.writeheader()
        for row in rows:
            writer.writerow(row_to_export_dict(row))


def sanitize_txt_part(value: object) -> str:
    """Keep one exported A:B:C record on a single physical line."""
    return str(value).replace("\r", " ").replace("\n", " ").strip()


def export_rows_to_txt(path: Path, rows: Sequence[TripleRow]) -> None:
    """Export TXT as one de-duplicated A:B:C record per line, without a header."""
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
        raise ValueError(f"不支持的导出格式: {export_format}")


class RgSearchGui(tk.Tk):
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
        default_rgs = Path(__file__).with_name("rgs.py")
        self.rgs_path_var = tk.StringVar(value=str(default_rgs))
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
        root.rowconfigure(7, weight=1)

        ttk.Label(root, text="rgs.py 路径").grid(row=0, column=0, sticky=tk.W, pady=3)
        rgs_frame = ttk.Frame(root)
        rgs_frame.grid(row=0, column=1, sticky=tk.EW, pady=3)
        rgs_frame.columnconfigure(0, weight=1)
        ttk.Entry(rgs_frame, textvariable=self.rgs_path_var).grid(row=0, column=0, sticky=tk.EW)
        ttk.Button(rgs_frame, text="选择", command=self._choose_rgs).grid(row=0, column=1, padx=(6, 0))

        ttk.Label(root, text="检索路径\n一行一个文件或目录").grid(row=1, column=0, sticky=tk.NW, pady=3)
        path_frame = ttk.Frame(root)
        path_frame.grid(row=1, column=1, sticky=tk.EW, pady=3)
        path_frame.columnconfigure(0, weight=1)
        self.paths_text = tk.Text(path_frame, height=3, wrap=tk.NONE)
        self.paths_text.grid(row=0, column=0, sticky=tk.EW)
        path_buttons = ttk.Frame(path_frame)
        path_buttons.grid(row=0, column=1, sticky=tk.N, padx=(6, 0))
        ttk.Button(path_buttons, text="添加目录", command=self._add_directory).pack(fill=tk.X)
        ttk.Button(path_buttons, text="添加文件", command=self._add_file).pack(fill=tk.X, pady=(4, 0))
        ttk.Button(path_buttons, text="清空路径", command=lambda: self.paths_text.delete("1.0", tk.END)).pack(fill=tk.X, pady=(4, 0))

        ttk.Label(root, text="关键词\n一行一个").grid(row=2, column=0, sticky=tk.NW, pady=3)
        self.keywords_text = tk.Text(root, height=3, wrap=tk.NONE)
        self.keywords_text.grid(row=2, column=1, sticky=tk.EW, pady=3)

        options = ttk.LabelFrame(root, text="检索选项")
        options.grid(row=3, column=0, columnspan=2, sticky=tk.EW, pady=(8, 4))
        for i in range(10):
            options.columnconfigure(i, weight=0)
        options.columnconfigure(9, weight=1)

        ttk.Label(options, text="字段").grid(row=0, column=0, sticky=tk.W, padx=(8, 4), pady=6)
        field_combo = ttk.Combobox(options, textvariable=self.field_var, values=list(FIELD_LABEL_TO_VALUE.keys()), state="readonly", width=18)
        field_combo.grid(row=0, column=1, sticky=tk.W, padx=(0, 12), pady=6)

        ttk.Checkbutton(options, text="正则", variable=self.regex_var).grid(row=0, column=2, sticky=tk.W, padx=(0, 12), pady=6)
        ttk.Checkbutton(options, text="忽略大小写", variable=self.ignore_case_var).grid(row=0, column=3, sticky=tk.W, padx=(0, 12), pady=6)
        ttk.Checkbutton(options, text="扫描隐藏/忽略/二进制文本", variable=self.all_files_var).grid(row=0, column=4, sticky=tk.W, padx=(0, 12), pady=6)
        ttk.Label(options, text="rg").grid(row=0, column=5, sticky=tk.W, padx=(0, 4), pady=6)
        ttk.Entry(options, textvariable=self.rg_bin_var, width=12).grid(row=0, column=6, sticky=tk.W, padx=(0, 12), pady=6)

        filters = ttk.LabelFrame(root, text="可选过滤 / 性能参数")
        filters.grid(row=4, column=0, columnspan=2, sticky=tk.EW, pady=(4, 4))
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
        button_frame.grid(row=5, column=0, columnspan=2, sticky=tk.EW, pady=6)
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

        ttk.Label(root, textvariable=self.status_var).grid(row=6, column=0, columnspan=2, sticky=tk.EW, pady=(2, 6))

        result_pane = ttk.Panedwindow(root, orient=tk.VERTICAL)
        result_pane.grid(row=7, column=0, columnspan=2, sticky=tk.NSEW)

        table_frame = ttk.Frame(result_pane)
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)
        self.tree = ttk.Treeview(table_frame, columns=("A", "B", "C", "file", "line"), show="headings")
        for column, width in (("A", 330), ("B", 190), ("C", 260), ("file", 260), ("line", 70)):
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

    def _choose_rgs(self) -> None:
        path = filedialog.askopenfilename(title="选择 rgs.py", filetypes=[("Python", "*.py"), ("All files", "*")])
        if path:
            self.rgs_path_var.set(path)

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

    def _make_config(self) -> SearchConfig:
        paths = parse_multiline_values(self.paths_text.get("1.0", tk.END))
        keywords = parse_keyword_values(self.keywords_text.get("1.0", tk.END))
        field = FIELD_LABEL_TO_VALUE.get(self.field_var.get(), "B")
        try:
            output_limit = int(self.output_limit_var.get().strip() or "0")
        except ValueError:
            raise ValueError("显示上限必须是整数。")
        if output_limit < 0:
            raise ValueError("显示上限不能小于 0。")

        return SearchConfig(
            rgs_path=Path(self.rgs_path_var.get()).expanduser(),
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
                rows = run_search(config, lambda msg: self.event_queue.put(("log", msg)), self.cancel_event)
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

        path = filedialog.asksaveasfilename(
            title=title,
            defaultextension=extension,
            filetypes=filetypes,
        )
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


def run_self_test() -> int:
    samples = [
        ("https://example.test/path:user1:pass1", ("https://example.test/path", "user1", "pass1")),
        ("https://example.test/path/:user2:pa:ss:2", ("https://example.test/path/", "user2", "pa:ss:2")),
        ("https://example.test:8443/path:user3:pass3", ("https://example.test:8443/path", "user3", "pass3")),
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

    with tempfile.TemporaryDirectory() as tmpdir:
        csv_path = Path(tmpdir) / "out.csv"
        txt_path = Path(tmpdir) / "out.txt"
        export_rows(csv_path, deduped, "csv")
        export_rows(txt_path, deduped, "txt")
        csv_lines = csv_path.read_text(encoding="utf-8-sig").splitlines()
        txt_lines = txt_path.read_text(encoding="utf-8").splitlines()
        if not csv_lines or csv_lines[0] != "A,B,C,file,line,source_line":
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

    print("self-test ok")
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    argv = list(argv if argv is not None else sys.argv[1:])
    if "--self-test" in argv:
        return run_self_test()
    app = RgSearchGui()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
