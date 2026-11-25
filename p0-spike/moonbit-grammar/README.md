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

## 复现

从本目录（`p0-spike/moonbit-grammar`）运行：

```sh
moon run --target native verify      # 期望: TOTAL=31 OK=31 ERR=0
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
- 本 spike 未并入主 workspace（`sast-mbt/moon.work`），是独立模块，不影响现有 11 步验收。
- 若要产品化，下一步是规则集设计（MoonBit 生态危险 API），那是比 scanner 更大的工作量。
