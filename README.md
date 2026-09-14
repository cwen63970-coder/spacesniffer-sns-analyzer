# sns-analyzer · SpaceSniffer 快照分析器

解析 SpaceSniffer 导出的 `.sns` 二进制快照，输出磁盘空间分析报告（Markdown + CSV + JSON）。
零第三方依赖（Python 3.8+ 标准库），单文件脚本。

> **官方有没有分析工具？没有。** SpaceSniffer（作者 Umberto Uderzo）是免费软件，官网只提供 GUI 使用说明，
> `.sns` 导出格式**从未公开文档化**，也没有官方解析/导出 API。本文脚本的格式规范来自社区逆向
> （[jerrylususu/SpaceSniffer_Format](https://github.com/jerrylususu/SpaceSniffer_Format)、
> [zhkgo 的字节级分析](https://zhkgo.github.io/2024/04/30/snsData/)）**加上对一个 244 MB 真实 C 盘快照的第一手验证**
> （1,601,727 个文件 / 424,021 个目录全部解析通过、逐目录一致性校验通过）。

---

## 快速开始

```bash
# 1) 生成一个合成示例（无需真实快照即可试用）
python make_example.py example.sns

# 2) 导出文件树（主功能）
python sns_analyze.py example.sns --tree tree.txt --min 1

# 3) 分析你自己的快照（SpaceSniffer 中 File → Export 得到 .sns）
python sns_analyze.py "D:\scan\C_drive.sns" -o report --tree 文件树.txt --depth 8 --min 128 --json

# 4) 导出 JSON / Markdown 树，直接投喂大模型（用 --max-nodes 控制规模）
python sns_analyze.py "D:\scan\C_drive.sns" -o report --tree-json tree.json --max-nodes 2500
python sns_analyze.py "D:\scan\C_drive.sns" -o report --tree-md tree.md --max-nodes 2500

# 5) 只要目录结构、不要文件行
python sns_analyze.py "D:\scan\C_drive.sns" -o report --tree tree_dirs.txt --dirs-only

# 6) 可选：生成 Markdown 报告
python sns_analyze.py "D:\scan\C_drive.sns" -o report --report
```

### 参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `input` | 必填 | `.sns` 快照路径 |
| `--output, -o` | `.` | 输出目录 |
| `--tree PATH` | 无 | **导出层级文本树**（`├──/└──` 连线，目录带 `/` 和大小） |
| `--tree-json PATH` | 无 | **嵌套 JSON 树**（`name/size/size_h/type/children`，大模型友好） |
| `--tree-md PATH` | 无 | **Markdown 嵌套列表树**（`- 📁`，可直接粘贴进聊天工具） |
| `--depth N` | 0 | 树的最大深度（0 = 不限） |
| `--max-nodes N` | 0 | 树节点总数上限（按大小优先保留，防止输出超出大模型上下文，0 = 不限） |
| `--min N` | 128 | ≥ N MiB 的目录才展开（树与 `dirs.csv` 都受此控制）；更小的目录折叠为一行，文件 < N MiB 不显示 |
| `--dirs-only` | 关 | 树中不显示文件行（目录大小仍保留） |
| `--top` | 600 | 保留最大的 N 个文件 |
| `--subtree` | 无 | 分号分隔的路径前缀，导出完整子树 CSV，如 `"C:\$Recycle.Bin;D:\Games"` |
| `--report` | 关 | 额外生成 Markdown 报告（`report.md`） |
| `--lang` | `zh` | 报告语言 `zh` / `en` |
| `--json` | 关 | 额外输出 `summary.json` |

### 输出文件

| 文件 | 内容 |
|---|---|
| `tree.txt` | 层级文本树：分支连线、目录以 `/` 结尾、每项带逻辑大小；根行含容量/已用/空闲 |
| `tree.json` | 嵌套 JSON 树：每个节点 `name` / `size`(字节) / `size_h`(人类可读) / `type` / `children`，子项按大小降序 |
| `tree.md` | Markdown 嵌套列表树，`📁`/`📄` 图标 + 大小，可直接粘贴给 AI 工具 |
| `dirs.csv` | ≥ `--min` MiB 的目录及其直接子项（可自行透视） |
| `top_files.csv` | 最大的 N 个文件（逻辑大小 / 磁盘占用 / 完整路径） |
| `extensions.csv` | 扩展名统计（数量 + 大小） |
| `subtree_*.csv` | `--subtree` 指定的完整子树清单 |
| `report.md` | 可选（`--report`）：总览、一级目录、一致性校验、扩展名、最大文件 |
| `summary.json` | 可选（`--json`）：聚合数字 |

---

## `.sns` 格式规范（逆向 + 实测）

小端序；整文件是一条记录流：

```
node  = 类型(2B) + 名字长度(4B) + base64名字 + 定长(46B) + [目录: 子项...] + 结束符 01 00
```

| 字段 | 长度 | 说明 |
|---|---|---|
| 类型 | 2B | `04 01`/`02 01` = 根(盘符)　`04 02`/`02 02` = 文件　`04 03`/`02 03` = 目录<br>`04 04` = Free Space（页脚）　`04 05` = Unknown Space（页脚） |
| 名字长度 | 4B | base64 字符串长度（字节） |
| 名字 | 变长 | **base64(UTF-16LE)**；中文/日文名原样保留 |
| 逻辑大小 | 8B | 文件 = 字节数；目录 = 子树递归合计；**根 = 整盘容量** |
| 磁盘大小 | 8B | 簇对齐后的占用 |
| 其他 | 30B | 本快照中目录为全 0（疑为时间戳区，未使用） |
| 结束符 | 2B | `01 00`；文件紧随其后，目录在其**全部子项之后** |

要点与坑：

- **根记录的大小是"整盘容量"，不是已用空间**；空闲空间在页脚 `Free Space`（`04 04`）记录里。
  已用 = 容量 − 空闲。这是最容易误读的地方。
- 类型首字节存在 `0x04` 与 `0x02` 两种版本差异，脚本两种都接受。
- 名字 base64 后**没有**填充到 4 字节边界以外的特殊处理，直接 `b64decode` 即可。
- 目录不会在子项之间插入分隔符；只有文件后和目录末尾各有一个 `01 00`。
- 快照里通常**看不到** `pagefile.sys` / `hiberfil.sys`（页面文件多在其他盘或已禁用时应自行核对）。

---

## 在真实数据上的验证

| 指标 | 结果 |
|---|---|
| 快照体积 | 244,443,690 字节（233 MiB） |
| 解析耗时 | ≈15 s（纯 Python 单遍扫描） |
| 文件 / 目录 | 1,601,727 / 424,021，最大深度 31 |
| 结构校验 | 解析恰好结束于文件末尾，无孤立结束符 |
| 一致性校验 | 除根外**所有目录**自报大小 = 子项合计 |
| 容量 / 空闲 / 已用 | 349.03 GiB / 56.92 GiB / 292.11 GiB |
| 树内文件合计 | 293.62 GiB（比已用多 0.5%，硬链接/稀疏文件等正常误差） |

---

## 注意事项

- **隐私**：生成的报告包含真实文件路径。公开分享前请自行删改；本仓库 `.gitignore` 已默认忽略
  `*.sns` 与输出目录，避免误传快照本身。
- 格式为社区逆向结果，不同 SpaceSniffer 版本可能微调；若解析报错，请附 `--json` 输出与错误偏移提 issue。
- 目录大小是 SpaceSniffer 记录的递归值，脚本不重新遍历磁盘；分析结果反映**快照时点**状态。
- 大规模快照（>1 GB / 千万级文件）内存占用主要来自名字解码与堆，建议先 `--top 2000` 试跑。

## English

`sns_analyze.py` parses SpaceSniffer `.sns` binary snapshots (undocumented format,
reverse-engineered and field-verified here). The primary export is a
**hierarchical file tree** — plain text (`--tree`), nested **JSON** (`--tree-json`,
with `name/size/size_h/type/children` per node) or **Markdown** (`--tree-md`) for
feeding directly to LLM tools; `--max-nodes` caps node count to fit context
windows. CSV/JSON exports (top files, extensions, per-directory children, optional
full subtrees and Markdown report) are also available. Stdlib-only, Python 3.8+.

```bash
python make_example.py example.sns
python sns_analyze.py example.sns -o out --tree tree.txt --min 1
python sns_analyze.py example.sns -o out --tree-json tree.json --max-nodes 500
python sns_analyze.py example.sns -o out --report --lang en
```

## 参考

- SpaceSniffer 官网：<http://www.uderzo.it/main_products/space_sniffer/>
- 格式逆向笔记：<https://github.com/jerrylususu/SpaceSniffer_Format>
- 字节级分析（中文）：<https://zhkgo.github.io/2024/04/30/snsData/>

## License

MIT
