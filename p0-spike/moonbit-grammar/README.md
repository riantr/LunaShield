# MoonBit grammar spike — 最小可行版本

目标：验证能否用本项目依赖的纯 MoonBit tree-sitter 移植（`moonbit-community/treesitter`）
解析 MoonBit 源码，跑通「external scanner 移植 + AST 生成」。**仅做解析，不含规则/报告/CLI 集成。**

## 结论：可行

- 官方 grammar `moonbitlang/tree-sitter-moonbit` 的 `grammar.json` 能被本项目的
  generator 直接消费，产出 8 个 external token 的 `Language`。
- `src/scanner.c`（550 行）已逐分支移植为 MoonBit（`pkg/scanner.mbt`，459 行）。
- 用官方 corpus 的 31 个真实用例（ASI / for / 浮点 / 多行串等）验证：
  **31/31 解析无 ERROR。**

## 结构

| 路径 | 内容 |
|---|---|
| `pkg/scanner.mbt` | external scanner 移植（8 token + 2 状态位 + ASI） |
| `pkg/language_tables.mbt` | 从 grammar.json 生成的 compact base64 解析表 |
| `pkg/binding.mbt` | `language()`：装 tables + 挂 scanner，带缓存 |
| `bin/main.mbt` | 重新生成 tables 的工具（generator） |
| `verify/main.mbt` | 批量解析 corpus/cases.json，统计 OK/ERROR |
| `corpus/cases.json` | 从官方 `test/corpus/{asi,for,literal}.txt` 提取的 31 个用例 |
| `grammar/grammar.json` | 上游 grammar（319 KB，用于重生成 tables） |
| `node-types.json` | 上游节点类型（392 项，257 named，全部无 fields） |
| `probe/main.mbt` | 11 个 query 探针：capture 稳定性 / 位置锚点 / 插值 / 多行串 / 空 catch |
| `QUERY_PATTERNS.md` | 规则 query 模板（探针实测结论，写规则前必读） |
| `rules_moonbit.json` | 首批 10 条 MoonBit 规则（MB001–MB010，schema 与官方包一致） |
| `rules_samples.json` | 每条规则的正例/反例源码与期望命中数 |
| `taint_moonbit.json` | MoonBit 语言块的 source / sanitizer / sink |
| `rules_check/main.mbt` | 规则验证：读两份 JSON，跑匹配+谓词，断言正反例命中数 |

## 首批 10 条规则验证：10/10 PASS

规则数据放在 `rules_moonbit.json`（唯一数据源），`rules_check` 用与
`libs/query-engine/engine.mbt` 相同的匹配和谓词语义，对每条规则的正例与反例
各跑一次，断言命中数等于 `rules_samples.json` 的期望值。10 条全部通过：

| ID | 风险 | CWE | 反例靠什么区分 |
|---|---|---|---|
| MB001 | `process.run` 命令注入 | 78 | 命令是字符串字面量（`not_has_prefix '"'`） |
| MB002 | `fs.read_file` 路径穿越 | 22 | API 换成 `write_file` |
| MB003 | 硬编码 API key | 798 | 字符串不带 `sk_` 前缀 |
| MB004 | `crypto.md5` 弱哈希 | 328 | API 换成 `sha256` |
| MB005 | `Rand::new()` 弱随机 | 338 | 换成 `Rand::chacha8()` |
| MB006 | `Tls::client(verify=false)` | 295 | `verify=true` |
| MB007 | env 值写日志 | 532 | 参数是字面量 |
| MB008 | `extern "C"` FFI 边界 | 1116 | 普通函数无 external_linkage |
| MB009 | HMAC digest=MD5 | 327 | `digest=SHA256` |
| MB010 | 空 catch 吞异常 | 390 | catch 内有 `case_clause` |

规则 JSON 的字段集合、severity 取值、谓词 kind 均与官方 `rules.json` schema
逐字段核对一致；`taint_moonbit.json` 的 sink `rule_id` 全部指向已声明规则。

## 复现

从本目录（`p0-spike/moonbit-grammar`）运行：

```sh
moon run --target native verify      # 期望: TOTAL=31 OK=31 ERR=0
moon run --target native probe       # 期望: PROBE TOTAL=11 PASS=11 FAIL=0
moon run --target native rules_check # 期望: RULES TOTAL=10 PASS=10 FAIL=0
```

重新生成解析表（仅在 grammar.json 变更时需要）：

```sh
mkdir -p out
moon run --target native bin
# 把 out/language_tables.txt 切成 96 字符一行、每行加 "#|" 前缀，
# 写回 pkg/language_tables.mbt 的 `let language_tables : String =` 之后。
```

## 已知事项

- 上游 `bindings/` 只有 C/Go/Node/Python/Rust/Zig，无 MoonBit 绑定；
  `moonbit-community/tree_sitter_mbt` 是空仓库。本 spike 的绑定是自制的。
- C 侧 `iswblank`（空格/制表）在 MoonBit ctype 中缺失，已在 scanner.mbt 内自建。
- 本 spike 仍是独立模块；其产物已产品化并入主工程：`grammars/moonbit/`（绑定 +
  scanner + tables）、`lang-registry` 的 `moonbit`/`.mb` 注册、官方规则包 MB001–MB010
  与 `taint.json` 的 moonbit 块。主工程 11 步验收已覆盖（golden 60/60、分片等价）。
- 规则集设计（MoonBit 生态危险 API）已落地首批 10 条；后续扩容仍以
  `QUERY_PATTERNS.md` 的位置锚点模板为准。
- query 探针已确认 tree-sitter Query 可用，但 grammar 无 named field，
  query 必须按 `QUERY_PATTERNS.md` 的位置锚点模板写；`@call` 的 capture index
  最大，engine 的 primary 会落在第一个子 capture（如 `@pkg`），与现有 JS 规则
  primary=callee 行为一致。
- 三个实测坑已记入 `QUERY_PATTERNS.md`：`fn` capture 带前导点、多行串 content
  带闭合 `|#`、原生谓词必须和 capture 包在同一对外层括号内。
