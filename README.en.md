# rg-search

[English](README.en.md) | [中文](README.md)

[![Python](https://img.shields.io/badge/Python-3.x-blue.svg)](https://www.python.org/)
[![ripgrep](https://img.shields.io/badge/Powered%20by-ripgrep-orange.svg)](https://github.com/BurntSushi/ripgrep)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

`rg-search` is a high-speed folder content search tool powered by [`ripgrep`](https://github.com/BurntSushi/ripgrep).

It is designed for large directories, code repositories, logs, configuration files, and multi-keyword search scenarios.  
The tool supports fast recursive search, result deduplication, keyword files, multiple output formats, directory exclusion, file filtering, and summary report generation.

---

## Features

- Fast recursive folder content search
- Multi-keyword search
- Load keywords from a file
- Fixed-string search by default for speed and safety
- Optional regex search
- Output formats: `TXT`, `CSV`, `JSONL`, `Markdown`
- Result deduplication
- Memory-based and SQLite-based dedupe
- Include / exclude glob filtering
- Search hidden files and ignored files
- Optional binary-as-text search
- Progress display
- Summary report generation
- Suitable for large-scale scans

---

## Requirements

- Python 3.x
- [`ripgrep`](https://github.com/BurntSushi/ripgrep)

Check whether `ripgrep` is installed:

```bash
rg --version
```

Install ripgrep:

### Ubuntu / Debian

```bash
sudo apt update
sudo apt install ripgrep
```

### macOS

```bash
brew install ripgrep
```

### Windows

Using Scoop:

```powershell
scoop install ripgrep
```

Using Chocolatey:

```powershell
choco install ripgrep
```

---

## Quick Start

Search multiple keywords in a folder:

```bash
python3 rgs.py -p /data -k password token secret
```

Save results to a JSONL file:

```bash
python3 rgs.py -p /data -k password token secret -o result.jsonl
```

Export results as CSV:

```bash
python3 rgs.py -p /data -k password token secret -o result.csv --format csv
```

---

## Basic Usage

```bash
python3 rgs.py -p <path> -k <keywords> [options]
```

Example:

```bash
python3 rgs.py -p /data -k password token secret -o result.jsonl --format jsonl
```

| Option | Description |
|---|---|
| `-p /data` | Search inside `/data` |
| `-k password token secret` | Search for multiple keywords |
| `-o result.jsonl` | Save results to `result.jsonl` |
| `--format jsonl` | Output results in JSONL format |

---

## Search Multiple Paths

```bash
python3 rgs.py -p /data /logs /backup -k password secret -o result.jsonl
```

---

## Keyword File

Create a keyword file:

```text
password
token
secret
api_key
access_key
```

Run search with the keyword file:

```bash
python3 rgs.py -p /data --keyword-file keywords.txt -o result.jsonl
```

You can also combine command-line keywords and a keyword file:

```bash
python3 rgs.py -p /data -k password --keyword-file keywords.txt -o result.jsonl
```

---

## Output Formats

### JSONL

```bash
python3 rgs.py -p /data -k password -o result.jsonl --format jsonl
```

Example output:

```json
{"file":"/data/config.txt","line":12,"column":8,"content":"db_password=123456","matches":["password"],"submatches":[{"start":3,"end":11,"text":"password"}],"absolute_offset":1234}
```

### CSV

```bash
python3 rgs.py -p /data -k password -o result.csv --format csv
```

CSV columns:

```text
file,line,column,matches,content
```

### TXT

```bash
python3 rgs.py -p /data -k password -o result.txt --format txt
```

Output format:

```text
/path/to/file:line:column: matched content
```

### Markdown

```bash
python3 rgs.py -p /data -k password -o result.md --format md
```

---

## Result Deduplication

By default, results are deduplicated by content:

```bash
--dedupe content
```

Disable dedupe:

```bash
python3 rgs.py -p /data -k password --dedupe none
```

Dedupe by content:

```bash
python3 rgs.py -p /data -k password --dedupe content
```

Dedupe by file and content:

```bash
python3 rgs.py -p /data -k password --dedupe file-content
```

Dedupe by file, line, and content:

```bash
python3 rgs.py -p /data -k password --dedupe line
```

---

## Large Result Deduplication

For very large result sets, use SQLite-based deduplication:

```bash
python3 rgs.py \
  -p /data \
  --keyword-file keywords.txt \
  -o result.jsonl \
  --format jsonl \
  --dedupe content \
  --dedupe-store sqlite
```

Keep the SQLite dedupe database:

```bash
--keep-dedupe-db
```

Specify a custom dedupe database path:

```bash
--dedupe-db dedupe.sqlite
```

---

## File Filtering

Search only Python files:

```bash
python3 rgs.py -p /project -k password --glob "*.py"
```

Search C / header files:

```bash
python3 rgs.py -p /project -k OpenWrt --glob "*.c" --glob "*.h"
```

Search config files:

```bash
python3 rgs.py \
  -p /data \
  -k password \
  --glob "*.conf" \
  --glob "*.ini" \
  --glob "*.yaml" \
  --glob "*.yml"
```

---

## Exclude Directories

Exclude `.git` and `node_modules`:

```bash
python3 rgs.py \
  -p /project \
  -k password token \
  --exclude .git \
  --exclude node_modules
```

Exclude Python virtual environments and cache folders:

```bash
python3 rgs.py \
  -p /project \
  -k password \
  --glob "*.py" \
  --exclude .venv \
  --exclude venv \
  --exclude __pycache__
```

---

## Search Hidden / Ignored / Binary Files

Search as much content as possible:

```bash
python3 rgs.py -p /data -k secret --all
```

`--all` enables:

- `--hidden`
- `--no-ignore`
- `--text`

You can also use them separately:

```bash
--hidden
--no-ignore
--text
```

---

## Regex Search

Fixed-string search is used by default. This is faster and safer for normal keywords.

Use regex mode when needed:

```bash
python3 rgs.py -p /data -k "1[3-9][0-9]{9}" --regex -o phones.jsonl
```

Use multiline regex:

```bash
python3 rgs.py -p /data -k "BEGIN[\s\S]*?END" --regex --multiline
```

> Multiline regex can be slower. Use it only when necessary.

---

## Performance Options

Set thread count:

```bash
python3 rgs.py -p /data -k password --threads 8
```

Skip very large files:

```bash
python3 rgs.py -p /data -k password --max-filesize 100M
```

Limit matches per file:

```bash
python3 rgs.py -p /data -k password --max-count-per-file 20
```

Limit total output results:

```bash
python3 rgs.py -p /data -k password --limit 1000
```

---

## Progress and Debug

Show progress every 1000 raw matches:

```bash
python3 rgs.py -p /data -k password --progress-every 1000
```

Quiet mode:

```bash
python3 rgs.py -p /data -k password --quiet
```

Debug mode:

```bash
python3 rgs.py -p /data -k password --debug
```

---

## Summary Report

By default, a summary report is generated:

```text
<output-file>.summary.json
```

Example:

```bash
python3 rgs.py -p /data -k password -o result.jsonl
```

Generated files:

```text
result.jsonl
result.jsonl.summary.json
```

The summary report includes:

- Search paths
- Output file
- Output format
- Keyword count
- Search mode
- Dedupe mode
- Raw match count
- Written result count
- Deduped count
- Matched file count
- Top matched files
- Elapsed time
- Matches per second
- ripgrep return code
- Executed command

Disable summary report:

```bash
--no-summary
```

Specify summary path:

```bash
--summary report.json
```

---

## Recommended Commands

General search:

```bash
python3 rgs.py \
  -p /data \
  -k password token secret api_key \
  -o result.jsonl \
  --format jsonl \
  --dedupe content \
  --exclude .git \
  --exclude node_modules
```

Large directory search:

```bash
python3 rgs.py \
  -p /data \
  --keyword-file keywords.txt \
  -o result.jsonl \
  --format jsonl \
  --dedupe content \
  --dedupe-store sqlite \
  --progress-every 50000 \
  --exclude .git \
  --exclude node_modules
```

Sensitive information scan:

```bash
python3 rgs.py \
  -p /data \
  -k password passwd pwd token secret api_key access_key private_key \
  -o security_hits.jsonl \
  --format jsonl \
  --dedupe content \
  --dedupe-store sqlite \
  --exclude .git \
  --exclude node_modules
```

Log analysis:

```bash
python3 rgs.py \
  -p /var/log \
  -k ERROR WARNING CRITICAL \
  -o log_hits.jsonl \
  --format jsonl \
  --dedupe file-content
```

---

## Options

| Option | Description |
|---|---|
| `-p`, `--path` | File or directory path to search. Multiple paths are supported. |
| `-k`, `--keywords` | Keywords to search. Multiple keywords are supported. |
| `--keyword-file` | Load keywords from a file, one keyword per line. |
| `-o`, `--output` | Output file path. |
| `--format` | Output format: `txt`, `csv`, `jsonl`, `md`. |
| `--summary` | Custom summary JSON path. |
| `--no-summary` | Disable summary report generation. |
| `--regex` | Enable regex search mode. |
| `--multiline` | Enable multiline regex search. |
| `--ignore-case` | Case-insensitive search. |
| `--case-sensitive` | Case-sensitive search. |
| `--smart-case` | Smart case mode. |
| `--glob` | Include files matching a glob pattern. Can be repeated. |
| `--exclude` | Exclude files or directories. Can be repeated. |
| `--all` | Search hidden files, ignored files, and binary files as text. |
| `--hidden` | Search hidden files. |
| `--no-ignore` | Do not respect ignore files. |
| `--text` | Treat binary files as text. |
| `--follow` | Follow symbolic links. |
| `--mmap` | Enable memory-mapped search. |
| `--no-mmap` | Disable memory-mapped search. |
| `--threads` | Number of ripgrep threads. `0` means auto. |
| `--max-filesize` | Skip files larger than this size. |
| `--max-columns` | Skip very long lines. |
| `--max-count-per-file` | Limit matches per file. |
| `--limit` | Limit total written results. |
| `--dedupe` | Dedupe mode: `none`, `line`, `content`, `file-content`. |
| `--dedupe-store` | Dedupe backend: `memory`, `sqlite`. |
| `--dedupe-db` | Custom SQLite dedupe database path. |
| `--keep-dedupe-db` | Keep auto-created SQLite dedupe database. |
| `--dedupe-trim` | Trim leading and trailing whitespace before dedupe. |
| `--no-dedupe-trim` | Do not trim whitespace before dedupe. |
| `--dedupe-collapse-space` | Collapse repeated whitespace before dedupe. |
| `--dedupe-ignore-case` | Ignore case when deduplicating. |
| `--progress-every` | Show progress every N raw matches. |
| `--quiet` | Disable progress output. |
| `--debug` | Show debug information. |
| `--rg-bin` | Custom ripgrep executable path. |

---

## FAQ

### ripgrep executable not found

Install ripgrep first, or specify the path manually:

```bash
python3 rgs.py -p /data -k password --rg-bin /usr/local/bin/rg
```

### Why are there fewer results than expected?

Possible reasons:

- Result deduplication is enabled by default
- `--glob` limits file types
- `--exclude` excludes directories
- `--max-count-per-file` limits matches per file
- `--limit` limits total output

To disable deduplication:

```bash
--dedupe none
```

### How to search special characters?

Fixed-string search is used by default, so special characters are treated literally.

Example:

```bash
python3 rgs.py -p /data -k "a.b*c?"
```

Use `--regex` only when you want regex behavior.

### What should I do if the result file is too large?

Recommended options:

```bash
--dedupe content
--dedupe-store sqlite
--max-filesize 500M
--exclude node_modules
--exclude .git
```

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Matches found |
| `1` | No matches found, treated as normal |
| Other | Execution error |

Use `--debug` to view more details.

---

## Project Description

A fast folder content search tool powered by ripgrep, with multi-keyword search, result deduplication, multiple output formats, and summary report generation.
