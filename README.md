# LunaShield

LunaShield（原研究代号 sast-mbt）是一个用 MoonBit 编写的源代码静态安全分析（SAST）工具，
对标 Kiuwan Code Security 的核心扫描能力。

## 当前能力（MVP，M0-M5 全部完成）

- **11 种语言**：JavaScript / TypeScript / TSX / Python / Java / JSON / MoonBit / C# / Go / Rust / PHP（tree-sitter grammar；MoonBit 绑定内置于 `grammars/moonbit/`）
- **64 条内置规则**（`rulepacks/official/`）：注入、XSS、硬编码密钥、反序列化、弱加密、配置缺陷等；MB001–MB010 为 MoonBit 首批，CS001/GO001/RS001/PHP001 为 P3 语言扩展首批
- **宿主谓词白名单**（16 种：8 种基础 + 8 种 `*_ignore_case`，固定集合，规则不可执行任意代码）+ tree-sitter 原生谓词；
  大小写不敏感谓词只折叠 ASCII，非 ASCII 字符保持原样、跨目标行为一致
- **确定性输出**：结果排序键覆盖全部字段、无时间戳、路径统一相对 POSIX，同输入两次运行逐字节相同
- **四种报告**：Console / JSON / JUnit / SARIF 2.1.0（`findings.json`、`junit.xml`、`findings.sarif`）
- **容错**：语法错误产出 ParseWarning 不中断扫描；二进制/超大/非法 UTF-8 文件分类跳过
- **抑制语法**：`// sast-ignore`、`// sast-ignore-next-line`、`// sast-ignore: JS001,JS003`
- **分片**：`--shard i/n`（FNV-1a over UTF-8，跨平台一致）
- **增量扫描**：`--incremental --cache-dir <dir>`（键 = path + 内容哈希 + 规则包摘要 + 分析器版本）
- **快速判活**：`--fast-cache`（隐含 `--incremental`）用 `(size, mtime)` 旁路 probe 命中缓存条目不读文件内容；
  12MB 语料重复扫描 381ms → 139ms。代价是 mtime 不可作为内容证明，默认关闭
- **baseline**：`--baseline <report.json>` 按 fingerprint 只报新增；SARIF 输出 `baselineState`
- **HTML 报告**：`--format html` 生成转义后的 `findings.html`
- **可复用 GitHub Action**：`.github/actions/lunashield`，固定 LunaShield ref 后在调用方仓库扫描
- **CLI 退出码**：0 干净 / 1 门禁命中 / 2 配置或规则错误 / 3 不可恢复错误

实测指标（`scripts/check_golden.py`）：**检出率 100%（64/64），反例误报率 0%**。

## 快速开始

```bash
cd sast-mbt
bash scripts/verify.sh          # 12 步全量验收（依赖拉取、补丁门禁、check/test/fmt、rules-validate、cram、golden、覆盖率、分片等价、WASM 构建）
python3 scripts/p2_loop.py      # P2 剩余门禁循环检查（S5/S6/S4c/MCIL/Benchmark/verify）
python3 scripts/p3_loop.py      # P3 生态门禁循环检查（分发/HTML/Action/WASM/语言扩展/verify）
moon build --target native --release apps/scan

# 扫描
./_build/native/release/build/sast/scan/scan.exe <target-dir> --format console --fail-on high
```

## 仓库结构

```
sast-mbt/            MVP 工程主体（grammars/moonbit + libs/* + apps/scan + apps/rules-validate + rulepacks + tests）
p0-spike/            P0 技术验证 spike（grammar 兼容、并发、缓存、端到端）
MoonBit_SAST_核心功能设计与实现规划.md   主规划
P1_MVP_实施方案.md                      MVP 实施方案与逐里程碑实测记录
P2_路线与实测.md                        P2（SARIF/Reporter/增量/污点）步骤与实测
```

## CI

`.github/workflows/ci.yml` 定义了 ubuntu-latest 与 windows-latest 双平台矩阵，
运行同一 `scripts/verify.sh`，工具链经 `moonup` 锁定 `0.10.21+06da1ed44`。
（当前仓库托管在 Gitee；托管到 GitHub 时该工作流即可生效。）

## 许可证

Apache-2.0
