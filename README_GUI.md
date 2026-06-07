# rg-search GUI 增补说明

本增补采用**非破坏式修改**：不覆盖、不删除、不重写原仓库的 `rgs.py`，只新增 `rgs_gui.py` 作为图形化入口。原命令行用法保持不变。

## 已完成的功能

- 图形化选择 `rgs.py`、检索目录或文件、关键词、字段和输出选项。
- 支持三段式文本 `A:B:C` 的字段检索：
  - 任意字段 A/B/C
  - A 字段
  - B 字段
  - C 字段
- 针对 URL 形式的 A 字段做了特殊解析，避免把 `https://` 中的冒号误当成字段分隔符。
- C 字段允许继续包含冒号，例如 `URL:user:pa:ss` 会被解析为：
  - A = `URL`
  - B = `user`
  - C = `pa:ss`
- 检索后按 `A -> B -> C` 进行排序和去重：
  - A 相同则比较 B。
  - B 也相同则比较 C。
  - 只有 A、B、C 三项完全相同才删除重复记录。
- 结果表格中 A、B、C 独立成列，并保留 `file` 和 `line` 便于审计定位。
- 支持导出 CSV 表格，字段为 `A,B,C,file,line,source_line`。

## 放置方式

把 `rgs_gui.py` 放到原仓库根目录，也就是和 `rgs.py` 同级：

```text
rg-search/
├── rgs.py
├── rgs_gui.py
├── README.md
└── requirements.txt
```

如果不放在同级，也可以在 GUI 顶部手动选择 `rgs.py` 路径。

## 运行方式

```bash
python3 rgs_gui.py
```

Windows 可使用：

```powershell
python rgs_gui.py
```

## 依赖

沿用原仓库依赖：

- Python 3.x
- ripgrep，也就是 `rg` 命令

GUI 使用 Python 标准库 `tkinter`，不需要新增 pip 包。Linux 桌面环境如果缺少 Tkinter，可安装系统包，例如：

```bash
sudo apt install python3-tk
```

## 字段检索逻辑

GUI 先调用原 `rgs.py` 输出临时 JSONL，然后对命中内容进行三段式解析和字段过滤。这样做可以最大程度复用原仓库的高速 ripgrep 检索能力，同时避免破坏原 CLI。

解析规则：

1. URL 风格 A 字段会跳过 `://`。
2. 找到 A 后，第一个冒号分隔 B。
3. B 后面的所有剩余内容都归入 C，因此 C 可以包含冒号。
4. 非 URL 文本使用 `split(':', 2)` 的三段式解析方式。

## 自检

```bash
python3 rgs_gui.py --self-test
```

预期输出：

```text
self-test ok
```

## 安全测试注意事项

此 GUI 只对本地选定文件或目录进行检索和解析，不联网、不上传、不修改源数据文件。导出的 CSV 可能包含敏感测试数据，请只在授权环境内保存和传输。
