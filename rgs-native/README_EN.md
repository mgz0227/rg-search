# rgs-native

`rgs-native` is a brand-new **C++20 native A/B/C field searcher**.

It does not use Python, SQLite, or a ripgrep subprocess in the default fast path. The core pipeline is:

```text
memory-mapped file -> parallel line scan -> keyword candidate filter -> A/B/C parse -> field match -> in-memory set de-duplication -> streamed output
```

It is designed for three-part records such as:

```text
A:B:C
https://example.com/login:user:pass
https://example.com:8443/path:user:pa:ss
```

The `A` field may be a URL. The parser understands `https://` and common URL ports; the `C` field may contain additional colons.

> Use this tool only on local files and data you are authorized to review. Do not use it for unauthorized data collection, account access, or credential misuse.

---

## Features

- **No Python**: one native C++20 executable.
- **No SQLite**: de-duplication uses an in-memory set for speed.
- **Interactive launcher by default**: run `rgs` and choose CLI or GUI.
- **Interactive CLI wizard**: Chinese prompts for fast local scanning.
- **Browser GUI**: starts a local `127.0.0.1` web interface.
- **Parse and search on the fly**: no intermediate JSONL or full-result buffering.
- **A/B/C field search**: supports `ANY`, `A`, `B`, and `C`.
- **Table output for B-field searches**: default columns are `A,B,C`.
- **A -> B -> C de-duplication**: only identical `(A,B,C)` triples are removed.
- **URL-aware parser**: supports `https://host/path:B:C` and `https://host:8443/path:B:C`.
- **Parallel scanning**: defaults to the CPU core count.
- **Memory-mapped reads**: reduces copies for large files.
- **CSV/TXT/JSONL outputs**: CSV includes a UTF-8 BOM for Excel compatibility.

---

## Build

### Linux / macOS

```bash
make
./rgs --self-test
```

or:

```bash
./build_linux.sh
```

### CMake

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
./build/rgs --self-test
```

### Windows MinGW

```bat
build_windows_mingw.bat
```

Manual command:

```bat
g++ -std=c++20 -O3 -DNDEBUG -pthread src\rgs.cpp -lws2_32 -o rgs.exe
rgs.exe --self-test
```

---

## Launch modes

### Default launcher

```bash
./rgs
```

Menu:

```text
1) Interactive fast CLI
2) Browser GUI
q) Quit
```

### Interactive CLI directly

```bash
./rgs --cli
```

### GUI directly

```bash
./rgs --gui
```

The GUI starts a local browser page:

```text
http://127.0.0.1:17627/
```

### Direct scan mode for scripts

```bash
./rgs scan -p ./data -k conapobre --field B -o result.csv --glob "*.txt"
```

---

## Fastest recommended command

Fixed-string B-field CSV output, restricted to text files:

```bash
./rgs scan -p ./data -k conapobre --field B -o result.csv --format csv --columns abc --glob "*.txt" --quiet
```

Output:

```csv
A,B,C
https://mail.sapo.pt/registo/,conapobre,8Le:bD.Sga!hjxw
```

If your `A` field never contains a colon, for example:

```text
host:user:pass
```

use the fastest parser:

```bash
./rgs scan -p ./data -k user --field B -o result.csv --parse simple --glob "*.txt"
```

For URL-based A fields, keep the default parser:

```bash
./rgs scan -p ./data -k user --field B -o result.csv --parse urlpath --glob "*.txt"
```

---

## Examples

### Search the B field

```bash
./rgs scan -p ./data -k alice --field B -o b.csv --glob "*.txt"
```

### Search the A field

```bash
./rgs scan -p ./data -k example.com --field A -o a.csv --glob "*.txt"
```

### Search the C field

```bash
./rgs scan -p ./data -k "bD.Sga" --field C -o c.csv --glob "*.txt"
```

### Search any field

```bash
./rgs scan -p ./data -k kenhub --field ANY -o any.csv --glob "*.txt"
```

### Multiple keywords

```bash
./rgs scan -p ./data -k alice -k bob -k carol --field B -o users.csv --glob "*.txt"
```

### Keyword file

```bash
./rgs scan -p ./data --keyword-file keywords.txt --field B -o result.csv --glob "*.txt"
```

### Full metadata columns

Default `--columns abc` is fastest. Use full columns only when you need source information:

```bash
./rgs scan -p ./data -k alice --field B -o full.csv --columns full --keep-matches --glob "*.txt"
```

Columns:

```text
A,B,C,file,line,source_line,matches
```

### Disable de-duplication

```bash
./rgs scan -p ./data -k alice --field B -o result.csv --no-dedupe
```

### Limit threads

```bash
./rgs scan -p ./data -k alice --field B -o result.csv --threads 8
```

### Limit output rows

```bash
./rgs scan -p ./data -k alice --field B -o result.csv --limit 100000
```

### Skip large files

```bash
./rgs scan -p ./data -k alice --field B -o result.csv --max-filesize 500M
```

### Write a summary JSON

Summary output is off by default to reduce extra I/O. Enable it with:

```bash
./rgs scan -p ./data -k alice --field B -o result.csv --summary summary.json
```

---

## Options

| Option | Description |
|---|---|
| `scan` | direct scan subcommand |
| `--cli` | launch the interactive CLI |
| `--gui` | launch the local browser GUI |
| `-p, --path` | file or directory; repeatable |
| `-k, --keyword` | keyword; repeatable |
| `--keyword-file` | one keyword per line |
| `-o, --output` | output file |
| `--field ANY/A/B/C` | field to search, default `B` |
| `--format csv/txt/jsonl` | output format, default `csv` |
| `--columns abc/full` | `abc` is fastest; `full` includes metadata |
| `--parse urlpath/url/simple` | A/B/C parser |
| `--regex` | use regex; fixed strings are faster |
| `--ignore-case` | ASCII case-insensitive matching |
| `--no-dedupe` | disable A/B/C de-duplication |
| `--keep-matches` | fill the matches column in full output |
| `--glob` | include glob, repeatable |
| `--exclude` | exclude glob or path fragment, repeatable |
| `--max-filesize` | skip large files such as `200M`, `1G` |
| `--limit` | write at most N unique rows |
| `--threads` | thread count; defaults to CPU cores |
| `--summary` | write summary JSON |
| `--quiet` | quiet mode |
| `--self-test` | run built-in tests |

---

## Parser modes

### `urlpath` default

Best for common URL triples:

```text
https://host/path:B:C
https://host:8443/path:B:C
```

### `url`

More general URL-aware parsing.

### `simple`

Fastest parser. It only performs:

```text
split(':', 2)
```

Use it only when the `A` field never contains a colon.

---

## Performance tips

Fastest combination:

```bash
./rgs scan -p ./data -k KEY --field B --format csv --columns abc --parse urlpath --glob "*.txt" --quiet
```

Tips:

1. Prefer fixed strings; avoid `--regex` when speed matters.
2. Use `--glob "*.txt"` to reduce the file set.
3. Keep `--columns abc`; use `--columns full` only when needed.
4. Use `--parse simple` if your data format allows it.
5. Output to a local SSD rather than a network drive.
6. If your dataset has very few duplicates, `--no-dedupe` removes set overhead.

---

## Difference from the previous Python version

The previous Python implementation already had `--abc-ultra`, plain stream parsing, and in-memory de-duplication, but it still had interpreter overhead, object allocation overhead, and subprocess pipe overhead. `rgs-native` scans files directly in C++ and does not call Python, SQLite, or ripgrep by default.

Preserved behavior:

- A/B/C field parsing.
- `ANY/A/B/C` field search.
- B-field table output with A/B/C columns.
- Exact `(A,B,C)` de-duplication.
- CLI and GUI entry points.
