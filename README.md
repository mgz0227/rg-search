# rg-search / rgs.py

默认中文说明。English documentation: [README_EN.md](README_EN.md)

`rgs.py` 是一个基于 ripgrep 的本地高速三段式文本检索工具，主要面向本地授权安全测试、数据自查和日志审计场景。它默认处理一行一个 `A:B:C` 的数据，例如：

```text
https://example.com/login:username:password
host:user:pass
url:account:secret:with:colon
```

工具支持按 A、B、C 任意字段精确检索，并在检索过程中边扫描、边解析、边匹配、边去重、边写出，尽量减少 Python 侧解析和内存开销。

> 请只在你拥有权限的数据、系统和测试环境中使用本工具。

## 核心特性

- 默认启动时先选择 **CLI 交互式** 或 **GUI 图形界面**。
- CLI 交互式默认中文，不需要记参数。
- 大数据量推荐 CLI，高速路径默认开启。
- A/B/C 字段检索：`--field A`、`--field B`、`--field C`、`--field ANY`。
- 支持 URL 形式 A 字段，不会把 `https://` 误切分。
- 默认按 `(A, B, C)` 精确去重。
- 默认 CSV 输出只写 `A,B,C` 三列，速度最快。
- 可选完整输出列：`A,B,C,file,line,source_line,matches`。
- 不使用 SQLite，去重默认使用内存 set。
- 保留普通 ripgrep 检索模式，兼容非 A/B/C 文本搜索。

## 运行方式

### 默认启动菜单

```bash
python3 rgs.py
```

启动后会先出现选择菜单：

```text
1) CLI 交互式极速检索
2) GUI 图形界面
q) 退出
```

选择 `1` 会进入 CLI 交互式向导；选择 `2` 会打开 GUI。

### 直接进入 CLI 交互式

```bash
python3 rgs.py --cli
```

等价写法：

```bash
python3 rgs.py --interactive
```

### 直接进入 GUI

```bash
python3 rgs.py --gui
```

### 自动化 / 脚本模式

只要传入完整参数，就不会弹出交互式菜单，方便批处理：

```bash
python3 rgs.py -p ./data -k alice --field B -o result.csv --quiet --no-summary
```

## 环境要求

- Python 3.8+
- ripgrep：命令名通常是 `rg`
- GUI 需要 Python Tkinter 支持

确认 ripgrep 可用：

```bash
rg --version
```

如果 `rg` 不在 PATH，可以使用：

```bash
python3 rgs.py -p ./data -k alice --field B --rg-bin /path/to/rg
```

Windows 下也可以把 `rg.exe` 放到脚本同目录，或加入系统 PATH。

## 最快推荐命令

检索 B 字段，输出 CSV，只保留 A/B/C 三列：

```bash
python3 rgs.py -p ./data -k alice --field B -o result.csv --format csv --quiet --no-summary --glob "*.txt"
```

这条命令会启用默认 ultra 路径：

```text
ripgrep 粗筛 -> Python 边解析 A:B:C -> 字段匹配 -> 内存去重 -> 边写 CSV
```

## A/B/C 字段说明

假设输入行是：

```text
https://example.com/login:alice:Pass123
```

解析结果为：

| 字段 | 内容 |
|---|---|
| A | `https://example.com/login` |
| B | `alice` |
| C | `Pass123` |

默认解析模式是：

```bash
--abc-parse urlpath
```

适合常见的 URL/path:B:C 数据，例如：

```text
https://site.com/path:user:pass
https://site.com:8443/path:user:pass
```

如果你的 A 字段绝对不会包含冒号，例如严格是：

```text
host:user:pass
```

可以使用更快的简单切分：

```bash
--abc-parse simple
```

## 常用示例

### 检索 B 字段

```bash
python3 rgs.py -p ./data -k conapobre --field B -o b_result.csv --quiet --no-summary --glob "*.txt"
```

### 检索 A 字段

```bash
python3 rgs.py -p ./data -k bet365 --field A -o a_result.csv --quiet --no-summary --glob "*.txt"
```

### 检索 C 字段

```bash
python3 rgs.py -p ./data -k "bD.Sga" --field C -o c_result.csv --quiet --no-summary --glob "*.txt"
```

### 任意字段检索

```bash
python3 rgs.py -p ./data -k kenhub --field ANY -o any_result.csv --quiet --no-summary --glob "*.txt"
```

### 正则检索 B 字段

```bash
python3 rgs.py -p ./data -k "^admin" --field B --regex -o b_regex.csv --quiet --no-summary --glob "*.txt"
```

说明：带 `^`、`$` 这类字段锚点的正则，为保证字段级准确性，可能会自动切换到 `colon` 候选扫描，速度会低于固定字符串。

### 使用关键词文件

`keywords.txt` 每行一个关键词：

```text
alice
bob
charlie
```

运行：

```bash
python3 rgs.py -p ./data --keyword-file keywords.txt --field B -o result.csv --quiet --no-summary --glob "*.txt"
```

### 输出 TXT，每行一个 A:B:C

```bash
python3 rgs.py -p ./data -k alice --field B --format txt -o result.txt --quiet --no-summary
```

### 输出完整元数据列

```bash
python3 rgs.py -p ./data -k alice --field B -o full.csv --abc-columns full --quiet --no-summary
```

完整列包含：

```text
A,B,C,file,line,source_line,matches
```

如果要填充 `matches` 列：

```bash
python3 rgs.py -p ./data -k alice --field B -o full.csv --abc-columns full --abc-keep-matches --quiet --no-summary
```

注意：`--abc-columns full` 和 `--abc-keep-matches` 会增加解析和写出成本，超大数据量下建议只用默认 `abc` 三列。

### 关闭 A/B/C 去重

默认会按 `(A, B, C)` 精确去重。如果需要保留重复行：

```bash
python3 rgs.py -p ./data -k alice --field B --dedupe none -o result.csv --quiet --no-summary
```

## 交互式 CLI 流程

运行：

```bash
python3 rgs.py --cli
```

会依次询问：

1. 检索文件或目录路径
2. 关键词或正则表达式
3. 检索字段：A / B / C / ANY
4. 是否使用正则
5. 大小写模式：smart / ignore / case
6. 输出格式：csv / txt / jsonl / md
7. 输出列模式：abc / full
8. 解析模式：urlpath / url / simple
9. 输出文件
10. include glob / exclude glob
11. 最大文件大小、最大输出数量
12. 是否去重、是否静默、是否跳过 summary
13. 是否扫描隐藏文件、忽略文件和二进制文本

默认值以速度优先，直接回车即可采用推荐设置。

## GUI 使用

运行：

```bash
python3 rgs.py --gui
```

或运行：

```bash
python3 rgs.py
```

然后选择 `2`。

GUI 适合少量结果预览、手动选择路径、手动导出 CSV/TXT。超大数据量建议使用 CLI，因为 GUI 表格渲染本身会消耗较多时间和内存。

## 参数速查

| 参数 | 说明 |
|---|---|
| `-p, --path` | 要检索的文件或目录，可传多个 |
| `-k, --keywords` | 关键词，可传多个 |
| `--keyword-file` | 关键词文件，每行一个 |
| `--field` | A/B/C/ANY 字段检索，传入后自动启用 A/B/C 模式 |
| `--format` | 输出格式：csv/txt/jsonl/md |
| `-o, --output` | 输出文件 |
| `--regex` | 使用正则匹配，默认是固定字符串 |
| `--ignore-case` | 忽略大小写 |
| `--case-sensitive` | 区分大小写 |
| `--smart-case` | 智能大小写，CLI 默认策略 |
| `--glob` | 只包含指定 glob，可重复 |
| `--exclude` | 排除指定文件或目录，可重复 |
| `--all` | 扫描隐藏、忽略和二进制文本 |
| `--max-filesize` | 跳过大文件，例如 `200M` |
| `--limit` | 最多写出 N 条去重结果 |
| `--dedupe none` | 关闭去重 |
| `--abc-columns abc` | 只输出 A/B/C，最快 |
| `--abc-columns full` | 输出 A/B/C/file/line/source_line/matches |
| `--abc-parse urlpath` | 默认 URL/path:B:C 解析模式 |
| `--abc-parse simple` | A 字段不含冒号时最快 |
| `--abc-candidate-mode auto` | 自动选择候选扫描模式 |
| `--quiet` | 静默模式，减少终端输出 |
| `--no-summary` | 不写 summary JSON，速度更快 |
| `--gui` | 直接启动 GUI |
| `--cli, --interactive` | 直接启动 CLI 交互式向导 |
| `--self-test` | 运行内置测试 |

## 性能建议

最高速度建议：

```bash
python3 rgs.py -p ./data -k keyword --field B --format csv -o result.csv --quiet --no-summary --glob "*.txt" --abc-columns abc
```

优化建议：

- 固定字符串比正则快，尽量不要使用 `--regex`。
- 能限制文件类型就加 `--glob "*.txt"`。
- 只需要 A/B/C 时保持默认 `--abc-columns abc`。
- 不需要 summary 时使用 `--no-summary`。
- 大批量自动化时使用 `--quiet`。
- A 字段不含冒号时使用 `--abc-parse simple`。
- 不需要重复行时保持默认去重；如果你需要原始重复记录，使用 `--dedupe none`。
- GUI 不适合展示百万级结果，超大数据请用 CLI 输出到文件。

## 故障排查

### 找不到 ripgrep

错误类似：

```text
ripgrep executable not found
```

解决：

```bash
rg --version
```

确认可用，或者用：

```bash
python3 rgs.py --rg-bin /path/to/rg ...
```

### GUI 无法启动

如果提示 Tkinter 不可用，请安装 Python Tkinter，或者直接使用 CLI：

```bash
python3 rgs.py --cli
```

### 没有结果

检查：

- `--field` 是否选对，例如要搜用户名应使用 `--field B`。
- 是否被 `--glob` 或 `--exclude` 过滤掉。
- 是否使用了区分大小写。
- 输入行是否确实是可解析的 `A:B:C`。

### CSV 打开乱码

CSV 默认使用 `utf-8-sig` 写出，Excel 通常可以直接识别。如果仍有问题，可以用支持 UTF-8 的编辑器或表格工具打开。

## 开发和测试

运行内置测试：

```bash
python3 rgs.py --self-test
```

语法检查：

```bash
python3 -m py_compile rgs.py
```

## 升级方式

把新版 `rgs.py` 覆盖仓库根目录的旧文件即可：

```bash
cp rgs.py rgs.py.bak
# 覆盖新文件后：
python3 rgs.py --self-test
python3 rgs.py
```
