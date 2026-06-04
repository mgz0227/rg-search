# rg-search

[中文](README.md) | [English](README.en.md)

[![Python](https://img.shields.io/badge/Python-3.x-blue.svg)](https://www.python.org/)
[![ripgrep](https://img.shields.io/badge/Powered%20by-ripgrep-orange.svg)](https://github.com/BurntSushi/ripgrep)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

`rg-search` 是一个基于 [`ripgrep`](https://github.com/BurntSushi/ripgrep) 的高速文件夹内容检索工具，适合在大量文件、代码仓库、日志目录、配置目录中快速查找关键词，并将结果导出为 `JSONL`、`CSV`、`TXT` 或 `Markdown` 格式。

它支持多关键词检索、关键词文件、目录排除、文件类型过滤、结果去重、超大结果集 SQLite 去重、进度输出和自动生成汇总报告。

---

## 功能特点

- 极速递归搜索文件夹内容
- 支持多个关键词
- 支持从关键词文件批量读取关键词
- 默认使用固定字符串搜索，速度快且更安全
- 可切换为正则搜索
- 支持 `TXT`、`CSV`、`JSONL`、`Markdown` 输出
- 支持按内容、文件+内容、文件+行号+内容去重
- 支持内存去重和 SQLite 去重
- 支持隐藏文件、忽略 `.gitignore`、二进制按文本扫描
- 支持 include / exclude glob 过滤
- 自动生成 summary 统计报告
- 可限制最大输出结果数
- 可显示实时进度

---

## 环境要求

需要提前安装：

- Python 3.x
- [`ripgrep`](https://github.com/BurntSushi/ripgrep)，也就是 `rg` 命令

确认是否已安装 ripgrep：

```bash
rg --version
```

安装 ripgrep：

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

使用 Scoop：

```powershell
scoop install ripgrep
```

或使用 Chocolatey：

```powershell
choco install ripgrep
```

---

## 快速开始

搜索多个关键词：

```bash
python3 rgs.py -p /data -k password token secret
```

指定输出文件：

```bash
python3 rgs.py -p /data -k password token secret -o result.jsonl
```

输出为 CSV：

```bash
python3 rgs.py -p /data -k password token secret -o result.csv --format csv
```

---

## 基本用法

```bash
python3 rgs.py -p <path> -k <keywords> [options]
```

示例：

```bash
python3 rgs.py -p /data -k password token secret -o result.jsonl --format jsonl
```

| 参数 | 说明 |
|---|---|
| `-p /data` | 搜索 `/data` 目录 |
| `-k password token secret` | 搜索多个关键词 |
| `-o result.jsonl` | 输出到 `result.jsonl` |
| `--format jsonl` | 使用 JSONL 输出格式 |

---

## 搜索多个目录

```bash
python3 rgs.py -p /data /logs /backup -k password secret -o result.jsonl
```

---

## 使用关键词文件

当关键词很多时，可以把关键词写入文件，一行一个关键词。

`keywords.txt` 示例：

```text
password
token
secret
api_key
access_key
```

运行：

```bash
python3 rgs.py -p /data --keyword-file keywords.txt -o result.jsonl
```

也可以同时使用命令行关键词和关键词文件：

```bash
python3 rgs.py -p /data -k password --keyword-file keywords.txt -o result.jsonl
```

---

## 输出格式

### JSONL

```bash
python3 rgs.py -p /data -k password -o result.jsonl --format jsonl
```

示例输出：

```json
{"file":"/data/config.txt","line":12,"column":8,"content":"db_password=123456","matches":["password"],"submatches":[{"start":3,"end":11,"text":"password"}],"absolute_offset":1234}
```

### CSV

```bash
python3 rgs.py -p /data -k password -o result.csv --format csv
```

CSV 字段：

```text
file,line,column,matches,content
```

### TXT

```bash
python3 rgs.py -p /data -k password -o result.txt --format txt
```

输出格式：

```text
文件路径:行号:列号: 命中内容
```

### Markdown

```bash
python3 rgs.py -p /data -k password -o result.md --format md
```

---

## 结果去重

默认启用内容去重：

```bash
--dedupe content
```

### 不去重

```bash
python3 rgs.py -p /data -k password --dedupe none
```

### 按内容去重

```bash
python3 rgs.py -p /data -k password --dedupe content
```

### 按文件+内容去重

```bash
python3 rgs.py -p /data -k password --dedupe file-content
```

### 按文件+行号+内容去重

```bash
python3 rgs.py -p /data -k password --dedupe line
```

---

## 大结果集去重

如果结果非常大，建议使用 SQLite 去重：

```bash
python3 rgs.py \
  -p /data \
  --keyword-file keywords.txt \
  -o result.jsonl \
  --format jsonl \
  --dedupe content \
  --dedupe-store sqlite
```

保留 SQLite 去重数据库：

```bash
--keep-dedupe-db
```

指定 SQLite 去重数据库路径：

```bash
--dedupe-db dedupe.sqlite
```

---

## 文件过滤

只搜索 Python 文件：

```bash
python3 rgs.py -p /project -k password --glob "*.py"
```

搜索 C / H 文件：

```bash
python3 rgs.py -p /project -k OpenWrt --glob "*.c" --glob "*.h"
```

搜索配置文件：

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

## 排除目录

排除 `.git` 和 `node_modules`：

```bash
python3 rgs.py \
  -p /project \
  -k password token \
  --exclude .git \
  --exclude node_modules
```

排除虚拟环境和缓存目录：

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

## 搜索隐藏文件、忽略规则和二进制文件

尽可能完整扫描：

```bash
python3 rgs.py -p /data -k secret --all
```

`--all` 相当于开启：

- `--hidden`
- `--no-ignore`
- `--text`

也可以单独使用：

```bash
--hidden
--no-ignore
--text
```

---

## 正则搜索

默认使用固定字符串搜索，速度更快，也更适合普通关键词。

需要正则时使用：

```bash
python3 rgs.py -p /data -k "1[3-9][0-9]{9}" --regex -o phones.jsonl
```

多行正则：

```bash
python3 rgs.py -p /data -k "BEGIN[\s\S]*?END" --regex --multiline
```

> 多行正则会更慢，建议只在必要时使用。

---

## 性能控制

设置线程数：

```bash
python3 rgs.py -p /data -k password --threads 8
```

跳过超大文件：

```bash
python3 rgs.py -p /data -k password --max-filesize 100M
```

限制每个文件的命中数：

```bash
python3 rgs.py -p /data -k password --max-count-per-file 20
```

限制总输出结果数：

```bash
python3 rgs.py -p /data -k password --limit 1000
```

---

## 进度和调试

每 1000 条原始命中显示一次进度：

```bash
python3 rgs.py -p /data -k password --progress-every 1000
```

静默模式：

```bash
python3 rgs.py -p /data -k password --quiet
```

调试模式：

```bash
python3 rgs.py -p /data -k password --debug
```

---

## 汇总报告

默认会生成汇总文件：

```text
<输出文件>.summary.json
```

示例：

```bash
python3 rgs.py -p /data -k password -o result.jsonl
```

生成文件：

```text
result.jsonl
result.jsonl.summary.json
```

汇总报告包含：

- 搜索路径
- 输出文件
- 输出格式
- 关键词数量
- 搜索模式
- 去重模式
- 原始命中数量
- 写入结果数量
- 去重删除数量
- 命中文件数量
- Top 命中文件
- 总耗时
- 每秒命中速度
- ripgrep 返回码
- 实际执行命令

关闭汇总报告：

```bash
--no-summary
```

指定汇总报告路径：

```bash
--summary report.json
```

---

## 推荐命令

### 通用搜索

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

### 超大目录搜索

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

### 敏感信息扫描

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

### 日志分析

```bash
python3 rgs.py \
  -p /var/log \
  -k ERROR WARNING CRITICAL \
  -o log_hits.jsonl \
  --format jsonl \
  --dedupe file-content
```

---

## 参数说明

| 参数 | 说明 |
|---|---|
| `-p`, `--path` | 要搜索的文件或目录，可传多个 |
| `-k`, `--keywords` | 要搜索的关键词，可传多个 |
| `--keyword-file` | 从文件读取关键词，一行一个 |
| `-o`, `--output` | 输出文件路径 |
| `--format` | 输出格式：`txt`、`csv`、`jsonl`、`md` |
| `--summary` | 指定汇总 JSON 路径 |
| `--no-summary` | 不生成汇总报告 |
| `--regex` | 使用正则模式 |
| `--multiline` | 正则模式下启用多行匹配 |
| `--ignore-case` | 忽略大小写 |
| `--case-sensitive` | 严格区分大小写 |
| `--smart-case` | 智能大小写 |
| `--glob` | 包含指定 glob，可重复 |
| `--exclude` | 排除指定 glob 或目录，可重复 |
| `--all` | 搜索隐藏文件、忽略 ignore 规则、二进制按文本处理 |
| `--hidden` | 搜索隐藏文件 |
| `--no-ignore` | 不遵守 ignore 规则 |
| `--text` | 二进制按文本搜索 |
| `--follow` | 跟随符号链接 |
| `--mmap` | 使用内存映射 |
| `--no-mmap` | 关闭内存映射 |
| `--threads` | ripgrep 线程数，`0` 表示自动 |
| `--max-filesize` | 跳过超过指定大小的文件 |
| `--max-columns` | 跳过超长行 |
| `--max-count-per-file` | 每个文件最多命中数量 |
| `--limit` | 总输出结果数上限 |
| `--dedupe` | 去重模式：`none`、`line`、`content`、`file-content` |
| `--dedupe-store` | 去重存储：`memory`、`sqlite` |
| `--dedupe-db` | 指定 SQLite 去重数据库路径 |
| `--keep-dedupe-db` | 保留自动生成的 SQLite 去重数据库 |
| `--dedupe-trim` | 去重前去掉首尾空白 |
| `--no-dedupe-trim` | 去重前不去掉首尾空白 |
| `--dedupe-collapse-space` | 去重前合并连续空白 |
| `--dedupe-ignore-case` | 去重时忽略大小写 |
| `--progress-every` | 每多少条原始命中显示一次进度 |
| `--quiet` | 静默模式 |
| `--debug` | 调试模式 |
| `--rg-bin` | 指定 ripgrep 可执行文件路径 |

---

## 常见问题

### 提示 ripgrep executable not found

请先安装 ripgrep，或者手动指定路径：

```bash
python3 rgs.py -p /data -k password --rg-bin /usr/local/bin/rg
```

### 为什么结果比预期少？

可能原因：

- 默认启用了结果去重
- `--glob` 限制了文件类型
- `--exclude` 排除了目录
- `--max-count-per-file` 限制了每个文件的命中数
- `--limit` 限制了总输出数量

关闭去重：

```bash
--dedupe none
```

### 如何搜索特殊字符？

默认是固定字符串搜索，特殊字符会被当成普通字符处理。

示例：

```bash
python3 rgs.py -p /data -k "a.b*c?"
```

只有需要正则表达式时才使用 `--regex`。

### 结果文件太大怎么办？

推荐使用：

```bash
--dedupe content
--dedupe-store sqlite
--max-filesize 500M
--exclude node_modules
--exclude .git
```

---

## 退出码说明

| 退出码 | 含义 |
|---|---|
| `0` | 找到匹配结果 |
| `1` | 没有找到匹配结果，也视为正常 |
| 其他 | 执行异常 |

使用 `--debug` 可以查看更详细的信息。

---

## 项目简介

A fast folder content search tool powered by ripgrep, with multi-keyword search, result deduplication, multiple output formats, and summary report generation.
