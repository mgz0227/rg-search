# rg-search / rgs.py

Chinese documentation is the default: [README.md](README.md)

`rgs.py` is a fast local A:B:C field-search tool powered by ripgrep. It is designed for authorized local security testing, data review, and log auditing.

Typical input format:

```text
https://example.com/login:username:password
host:user:pass
url:account:secret:with:colon
```

The tool can search any A/B/C field and, in the fast path, streams the workflow as:

```text
ripgrep candidate scan -> parse A:B:C -> field match -> in-memory dedupe -> write output
```

> Use this tool only on data, systems, and testing environments you are authorized to assess.

## Features

- Default startup menu lets you choose **interactive CLI** or **GUI**.
- Chinese interactive CLI wizard for users who do not want to memorize flags.
- High-speed CLI mode recommended for large datasets.
- A/B/C field search: `--field A`, `--field B`, `--field C`, `--field ANY`.
- URL-aware parsing, so `https://` is not treated as the A/B separator.
- Exact `(A, B, C)` deduplication by default.
- Fast default CSV output with only `A,B,C` columns.
- Optional full output columns: `A,B,C,file,line,source_line,matches`.
- No SQLite; dedupe uses an in-memory set.
- Original ripgrep-style normal search mode is still available for non-A/B/C text.

## Startup modes

### Default launcher

```bash
python3 rgs.py
```

You will see:

```text
1) CLI interactive fast search
2) GUI
q) Quit
```

Choose `1` for the interactive CLI wizard, or `2` for the GUI.

### Direct interactive CLI

```bash
python3 rgs.py --cli
```

Equivalent:

```bash
python3 rgs.py --interactive
```

### Direct GUI

```bash
python3 rgs.py --gui
```

### Non-interactive / automation mode

When full arguments are supplied, no startup menu is shown:

```bash
python3 rgs.py -p ./data -k alice --field B -o result.csv --quiet --no-summary
```

## Requirements

- Python 3.8+
- ripgrep, usually available as `rg`
- Tkinter for GUI mode

Check ripgrep:

```bash
rg --version
```

If `rg` is not on PATH:

```bash
python3 rgs.py -p ./data -k alice --field B --rg-bin /path/to/rg
```

On Windows, you can also place `rg.exe` beside `rgs.py`, or add it to PATH.

## Fastest recommended command

Search the B field, export CSV, and keep only A/B/C columns:

```bash
python3 rgs.py -p ./data -k alice --field B -o result.csv --format csv --quiet --no-summary --glob "*.txt"
```

## A/B/C parsing

For this input:

```text
https://example.com/login:alice:Pass123
```

The parsed fields are:

| Field | Value |
|---|---|
| A | `https://example.com/login` |
| B | `alice` |
| C | `Pass123` |

The default parser is:

```bash
--abc-parse urlpath
```

It is optimized for common URL/path:B:C records, including:

```text
https://site.com/path:user:pass
https://site.com:8443/path:user:pass
```

If A never contains a colon, such as strict `host:user:pass`, use the faster parser:

```bash
--abc-parse simple
```

## Examples

### Search B field

```bash
python3 rgs.py -p ./data -k conapobre --field B -o b_result.csv --quiet --no-summary --glob "*.txt"
```

### Search A field

```bash
python3 rgs.py -p ./data -k bet365 --field A -o a_result.csv --quiet --no-summary --glob "*.txt"
```

### Search C field

```bash
python3 rgs.py -p ./data -k "bD.Sga" --field C -o c_result.csv --quiet --no-summary --glob "*.txt"
```

### Search any field

```bash
python3 rgs.py -p ./data -k kenhub --field ANY -o any_result.csv --quiet --no-summary --glob "*.txt"
```

### Regex search in B field

```bash
python3 rgs.py -p ./data -k "^admin" --field B --regex -o b_regex.csv --quiet --no-summary --glob "*.txt"
```

Field-anchored regexes such as `^` and `$` may switch to colon candidate scanning for field accuracy, which is slower than fixed-string search.

### Keyword file

`keywords.txt`:

```text
alice
bob
charlie
```

Run:

```bash
python3 rgs.py -p ./data --keyword-file keywords.txt --field B -o result.csv --quiet --no-summary --glob "*.txt"
```

### TXT output, one A:B:C per line

```bash
python3 rgs.py -p ./data -k alice --field B --format txt -o result.txt --quiet --no-summary
```

### Full metadata output

```bash
python3 rgs.py -p ./data -k alice --field B -o full.csv --abc-columns full --quiet --no-summary
```

Full columns:

```text
A,B,C,file,line,source_line,matches
```

To fill the `matches` column:

```bash
python3 rgs.py -p ./data -k alice --field B -o full.csv --abc-columns full --abc-keep-matches --quiet --no-summary
```

`--abc-columns full` and `--abc-keep-matches` add overhead. For very large datasets, prefer the default `abc` columns.

### Disable dedupe

Exact `(A, B, C)` dedupe is enabled by default. To keep repeated rows:

```bash
python3 rgs.py -p ./data -k alice --field B --dedupe none -o result.csv --quiet --no-summary
```

## Interactive CLI flow

Run:

```bash
python3 rgs.py --cli
```

The wizard asks for:

1. File or directory paths
2. Keywords or regex patterns
3. Field: A / B / C / ANY
4. Regex or fixed-string mode
5. Case mode: smart / ignore / case
6. Output format: csv / txt / jsonl / md
7. Column mode: abc / full
8. Parser mode: urlpath / url / simple
9. Output file path
10. Include/exclude globs
11. File size and result limits
12. Dedupe, quiet mode, summary output
13. Hidden/ignored/binary text scanning

Defaults are optimized for speed. Press Enter to accept the recommended value.

## GUI mode

Run:

```bash
python3 rgs.py --gui
```

Or run:

```bash
python3 rgs.py
```

and choose `2`.

The GUI is useful for previewing smaller result sets, selecting paths manually, and exporting CSV/TXT. For huge result sets, use CLI because table rendering can become the bottleneck.

## Options reference

| Option | Description |
|---|---|
| `-p, --path` | File or directory paths to search |
| `-k, --keywords` | One or more keywords |
| `--keyword-file` | File containing one keyword per line |
| `--field` | A/B/C/ANY field search; enables A/B/C mode |
| `--format` | Output format: csv/txt/jsonl/md |
| `-o, --output` | Output file |
| `--regex` | Use regex; fixed-string is the default |
| `--ignore-case` | Case-insensitive search |
| `--case-sensitive` | Case-sensitive search |
| `--smart-case` | Smart-case mode |
| `--glob` | Include glob; can be repeated |
| `--exclude` | Exclude glob or directory; can be repeated |
| `--all` | Search hidden, ignored, and binary-as-text files |
| `--max-filesize` | Skip large files, e.g. `200M` |
| `--limit` | Stop after N unique written rows |
| `--dedupe none` | Disable dedupe |
| `--abc-columns abc` | Output A/B/C only; fastest |
| `--abc-columns full` | Output A/B/C/file/line/source_line/matches |
| `--abc-parse urlpath` | Default URL/path:B:C parser |
| `--abc-parse simple` | Fastest parser when A has no colon |
| `--abc-candidate-mode auto` | Automatically choose candidate scanning mode |
| `--quiet` | Reduce terminal output |
| `--no-summary` | Do not write summary JSON |
| `--gui` | Launch GUI directly |
| `--cli, --interactive` | Launch interactive CLI directly |
| `--self-test` | Run built-in tests |

## Performance tips

Fastest pattern:

```bash
python3 rgs.py -p ./data -k keyword --field B --format csv -o result.csv --quiet --no-summary --glob "*.txt" --abc-columns abc
```

Tips:

- Fixed-string search is faster than regex.
- Use `--glob "*.txt"` when possible.
- Keep the default `--abc-columns abc` unless metadata is required.
- Use `--no-summary` if summary JSON is not needed.
- Use `--quiet` for large automated runs.
- Use `--abc-parse simple` if A never contains `:`.
- Keep dedupe on unless you need repeated raw records.
- Avoid GUI for million-row result sets.

## Troubleshooting

### ripgrep not found

Check:

```bash
rg --version
```

Or pass the binary path:

```bash
python3 rgs.py --rg-bin /path/to/rg ...
```

### GUI does not start

Install Python Tkinter, or use the CLI:

```bash
python3 rgs.py --cli
```

### No results

Check:

- Whether `--field` is correct.
- Whether `--glob` or `--exclude` filtered files out.
- Whether case sensitivity is blocking matches.
- Whether your input lines are valid A:B:C records.

### CSV encoding

CSV output uses `utf-8-sig`, which is usually Excel-friendly. If needed, open it with a UTF-8 capable editor or spreadsheet tool.

## Development and testing

Run built-in tests:

```bash
python3 rgs.py --self-test
```

Syntax check:

```bash
python3 -m py_compile rgs.py
```

## Upgrade

Replace the repository root `rgs.py` with the new file:

```bash
cp rgs.py rgs.py.bak
# replace rgs.py, then:
python3 rgs.py --self-test
python3 rgs.py
```
