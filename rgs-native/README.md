# rgs-native

`rgs-native` 是一套全新的 **C++20 原生 A/B/C 三段式极速检索工具**。

它不再使用 Python，不使用 SQLite，也不再默认调用 ripgrep。核心检索路径是：

```text
内存映射文件 -> 并行按行扫描 -> 候选关键词过滤 -> A/B/C 解析 -> 指定字段匹配 -> 内存 set 去重 -> 流式写出
```

适合处理这种三段式文本：

```text
A:B:C
https://example.com/login:user:pass
https://example.com:8443/path:user:pa:ss
```

其中 `A` 可以是 URL，解析器会正确跳过 `https://` 和常见端口；`C` 字段可以继续包含冒号。

> 本工具仅用于本机、授权范围内的数据审计、日志整理与安全测试。请勿用于未授权的数据收集、账号访问或凭据滥用。

---

## 主要特性

- **无 Python**：单个 C++20 原生可执行文件。
- **无 SQLite**：去重只用内存 set，速度优先。
- **默认交互式启动**：直接运行 `rgs` 先选择 CLI 或 GUI。
- **CLI 交互式向导**：选择 CLI 后继续用中文向导输入参数。
- **浏览器 GUI**：选择 GUI 后启动本地 `127.0.0.1` Web 界面。
- **边解析边检索**：不先生成中间文件，不先攒全量结果。
- **A/B/C 任意字段检索**：支持 `ANY`、`A`、`B`、`C`。
- **B 字段检索输出表格**：默认输出 `A,B,C` 三列。
- **按 A -> B -> C 去重**：只有完整 `(A,B,C)` 都一致才视为重复。
- **URL 友好解析**：支持 `https://host/path:B:C`、`https://host:8443/path:B:C`。
- **多线程扫描**：默认使用 CPU 核数。
- **内存映射读取**：大文件扫描减少复制开销。
- **CSV/TXT/JSONL 输出**：`csv` 默认写 UTF-8 BOM，方便 Excel 打开。

---

## 编译

### Linux / macOS

```bash
make
./rgs --self-test
```

或：

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

也可以手动编译：

```bat
g++ -std=c++20 -O3 -DNDEBUG -pthread src\rgs.cpp -lws2_32 -o rgs.exe
rgs.exe --self-test
```

---

## 启动方式

### 默认启动菜单

```bash
./rgs
```

会出现：

```text
1) CLI 交互式极速检索
2) GUI 浏览器界面
q) 退出
```

### 直接进入 CLI 交互式

```bash
./rgs --cli
```

### 直接进入 GUI

```bash
./rgs --gui
```

GUI 会启动本地服务并打开浏览器：

```text
http://127.0.0.1:17627/
```

### 直接参数模式，适合批处理

```bash
./rgs scan -p ./data -k conapobre --field B -o result.csv --glob "*.txt"
```

---

## 最快推荐命令

固定字符串、B 字段、CSV 三列表格、限定 txt 文件：

```bash
./rgs scan -p ./data -k conapobre --field B -o result.csv --format csv --columns abc --glob "*.txt" --quiet
```

输出：

```csv
A,B,C
https://mail.sapo.pt/registo/,conapobre,8Le:bD.Sga!hjxw
```

如果你的 A 字段绝对不会包含冒号，例如严格是：

```text
host:user:pass
```

可以使用最快解析器：

```bash
./rgs scan -p ./data -k user --field B -o result.csv --parse simple --glob "*.txt"
```

如果 A 字段是 URL，默认推荐：

```bash
./rgs scan -p ./data -k user --field B -o result.csv --parse urlpath --glob "*.txt"
```

---

## 常用示例

### 搜索 B 字段

```bash
./rgs scan -p ./data -k alice --field B -o b.csv --glob "*.txt"
```

### 搜索 A 字段

```bash
./rgs scan -p ./data -k example.com --field A -o a.csv --glob "*.txt"
```

### 搜索 C 字段

```bash
./rgs scan -p ./data -k "bD.Sga" --field C -o c.csv --glob "*.txt"
```

### 任意字段搜索

```bash
./rgs scan -p ./data -k kenhub --field ANY -o any.csv --glob "*.txt"
```

### 多关键词

```bash
./rgs scan -p ./data -k alice -k bob -k carol --field B -o users.csv --glob "*.txt"
```

### 关键词文件

```bash
./rgs scan -p ./data --keyword-file keywords.txt --field B -o result.csv --glob "*.txt"
```

`keywords.txt`：

```text
alice
bob
example.com
```

### 输出完整元数据

默认 `--columns abc` 只输出三列，最快。

需要文件名、行号、原始行、匹配关键词时：

```bash
./rgs scan -p ./data -k alice --field B -o full.csv --columns full --keep-matches --glob "*.txt"
```

输出列：

```text
A,B,C,file,line,source_line,matches
```

### 关闭去重

```bash
./rgs scan -p ./data -k alice --field B -o result.csv --no-dedupe
```

### 限制线程数

```bash
./rgs scan -p ./data -k alice --field B -o result.csv --threads 8
```

### 限制输出条数

```bash
./rgs scan -p ./data -k alice --field B -o result.csv --limit 100000
```

### 跳过大文件

```bash
./rgs scan -p ./data -k alice --field B -o result.csv --max-filesize 500M
```

### 写 summary JSON

默认不写 summary，减少额外 IO。需要时：

```bash
./rgs scan -p ./data -k alice --field B -o result.csv --summary summary.json
```

---

## 参数说明

| 参数 | 说明 |
|---|---|
| `scan` | 直接参数模式子命令 |
| `--cli` | 直接进入中文 CLI 交互式 |
| `--gui` | 启动本地浏览器 GUI |
| `-p, --path` | 文件或目录，可重复 |
| `-k, --keyword` | 关键词，可重复 |
| `--keyword-file` | 一行一个关键词 |
| `-o, --output` | 输出文件 |
| `--field ANY/A/B/C` | 要检索的字段，默认 `B` |
| `--format csv/txt/jsonl` | 输出格式，默认 `csv` |
| `--columns abc/full` | `abc` 最快；`full` 输出元数据 |
| `--parse urlpath/url/simple` | 三段式解析器 |
| `--regex` | 使用正则，通常比固定字符串慢 |
| `--ignore-case` | ASCII 忽略大小写，略慢 |
| `--no-dedupe` | 关闭 A/B/C 去重 |
| `--keep-matches` | full 输出时写 matches，略慢 |
| `--glob` | 包含 glob，例如 `*.txt`，可重复 |
| `--exclude` | 排除 glob 或目录片段，可重复 |
| `--max-filesize` | 跳过大文件，例如 `200M`、`1G` |
| `--limit` | 最多写出 N 条唯一结果 |
| `--threads` | 线程数，默认 CPU 核数 |
| `--summary` | 写 summary JSON |
| `--quiet` | 静默运行 |
| `--self-test` | 运行内置测试 |

---

## 解析模式

### `urlpath` 默认推荐

适合大多数 URL 三段式：

```text
https://host/path:B:C
https://host:8443/path:B:C
```

优先从 `scheme://` 后的路径位置寻找 A/B 分隔符，速度快。

### `url`

更通用的 URL 解析，适合 URL 形态不固定的文件。

### `simple`

最快，只做：

```text
split(':', 2)
```

仅适合 A 字段不包含冒号的格式，例如：

```text
host:user:pass
```

---

## 性能建议

最快组合：

```bash
./rgs scan -p ./data -k KEY --field B --format csv --columns abc --parse urlpath --glob "*.txt" --quiet
```

建议：

1. 优先使用固定字符串，不用 `--regex`。
2. 用 `--glob "*.txt"` 限定文件类型。
3. 默认 `--columns abc`，需要溯源时再用 `--columns full`。
4. 能使用 `--parse simple` 时会更快。
5. 输出到 SSD，本地磁盘比网络盘更快。
6. 数据极大且重复极少时，`--no-dedupe` 可以进一步减少内存 set 开销。

---

## 与旧 Python 版的区别

旧 Python 版已经做过 `--abc-ultra`、plain stream、内存 set 去重等优化，但仍然有 Python 解释器、对象分配和子进程管道开销。`rgs-native` 直接用 C++ 原生扫描文件，默认不再调用 Python、SQLite 或 ripgrep。

保留的行为：

- A/B/C 字段解析。
- `ANY/A/B/C` 任意字段检索。
- B 字段检索输出 A/B/C 表格。
- 按 `(A,B,C)` 精确去重。
- CLI 和 GUI 两种入口。

---

## 输出格式

### CSV

默认带 UTF-8 BOM，Excel 友好。

```csv
A,B,C
https://example.com/login,user,pass
```

### TXT

一行一个 A:B:C，无表头。

```text
https://example.com/login:user:pass
```

### JSONL

```json
{"A":"https://example.com/login","B":"user","C":"pass"}
```

# rgs-native 独立交互式去重版

新增独立 A/B/C 去重入口：不需要关键词，不进入普通 CLI 检索流程，也不启动 GUI。

## 启动方式

默认菜单：

```bash
./rgs
```

菜单中选择：

```text
3) 独立 A/B/C 去重
```

直接进入独立交互式去重：

```bash
./rgs --dedupe
./rgs dedupe
```

非交互直参模式仍然保留：

```bash
./rgs dedupe -p ./data -o deduped.txt --format txt --parse urlpath --glob "*.txt"
```

## 去重规则

独立去重模式会：

1. 读取目录下所有匹配文件。
2. 解析所有可解析的 A:B:C 行。
3. 全部读入内存。
4. 按 A -> B -> C 排序。
5. A 相同就比较 B，B 相同再比较 C。
6. 只有 A/B/C 三个字段完全一致才删除重复。
7. 输出最终结果。

## 编译

Linux：

```bash
g++ -std=c++20 -O3 -DNDEBUG -pthread rgs-native/src/rgs.cpp -o rgs
./rgs --self-test
```

Windows 交叉编译：

```bash
x86_64-w64-mingw32-g++ -std=c++20 -O3 -DNDEBUG \
  -static -static-libgcc -static-libstdc++ \
  rgs-native/src/rgs.cpp -o rgs-windows-x64.exe -lws2_32
```

---

## 注意事项

- `--ignore-case` 是 ASCII 忽略大小写，适合 URL、邮箱、用户名、ASCII 关键词。
- `--regex` 使用 C++ 标准库正则，灵活但不是最快路径。
- GUI 是本地浏览器 GUI，只监听 `127.0.0.1`，不会主动联网。
- 大量结果写 CSV 时，磁盘写入速度可能成为瓶颈。
