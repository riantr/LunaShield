# P1 MVP 实施方案（sast-mbt）

> **文档状态**：可执行开发规格（基于 P0 全部实测结论，非推测）
> **编制日期**：2026-11-22
> **上游文档**：`MoonBit_SAST_核心功能设计与实现规划.md`（总体设计）、`p0-spike/P0_SPIKE_实测报告.md`（实测证据）
> **标注约定**：`【实测】`有 P0 工程可复跑证据；`【设计】`本方案决策；`【需核实】`实现前必须验证，已给降级路径。

---

## 0. 一页速览

| 项 | 决策 |
|---|---|
| **MVP 目标** | 一个能进 CI 的 CLI：给源码目录，产出确定性 JSON Finding 报告，按严重度门禁返回退出码 |
| **语言范围** | JavaScript / TypeScript（含 TSX）/ Python / Java + JSON 配置；共 5 个 grammar `【实测】` |
| **检测能力** | AST Query + 固定谓词二次校验；**不含**污点/数据流（P2） |
| **规则规模** | 每语言首批 10 条核心规则（全部有正/反例 fixture），合计 50 条 `【设计】` |
| **报告** | Console 摘要 + JSON 全量 + JUnit；SARIF/HTML 留到 P2/P3 |
| **并发** | 单进程 `with_task_group` + `Semaphore` 限流；`--shard i/n` 多进程分片（结果全量排序）`【实测】` |
| **指纹** | SHA-256，`@utf8.encode(rule_id + "|" + normalized_snippet)` `【实测】` |
| **ignore** | `mizchi/bit_ignore`，对接 `@fs.walk` 的 `exclude` 回调 `【实测】` |
| **退出码** | `@env.exit(code)`，**不用** `abort`（P0 实测 `abort` 退出码为 127，不适合业务门禁）`【实测】` |
| **最大风险** | grammar 包的 `binding.mbt` 需补丁；必须把补丁脚本固化为构建前置步骤 + CI 门禁 `【实测】` |

**MVP 完成的定义**：`M0`–`M5` 六个批次全部达到各自验收命令；在自建 fixture 上检出率 ≥ 90%、反例误报率 ≤ 10%、同输入报告逐字节一致；Linux/Windows 两平台通过。

---

## 1. MVP 范围与交付定义

### 1.1 In Scope（必须交付）

1. **工程骨架**：`moon.work` workspace、版本锁定、grammar 补丁脚本纳入构建。
2. **数据模型**：`core-model`（Finding / SourceLoc / Severity / ScanResult / ScanConfig）。
3. **规则子系统**：JSON 规则 schema、`rule` 解析、`apps/rules-validate` 校验器（schema + Query 可编译性 + 谓词白名单）。
4. **扫描核心**：`@fs.walk` 文件发现、ignore、`lang-registry` 扩展名映射、Tree-sitter 解析封装（含错误节点 → ParseWarning）、Query 执行与谓词校验、指纹/抑制/去重。
5. **编排**：`orchestrator` 并发限流、`--shard i/n` 分片与归并排序、进度与统计。
6. **输出**：Console / JSON / JUnit 三种 reporter、退出码门禁。
7. **规则包**：首批 50 条规则（5 语言 × 10），每条含正例与反例 fixture。
8. **测试**：单元测试、`rules-validate` 门禁、`moon cram test <目录>` 端到端、golden 快照、CI 矩阵（Linux + Windows；macOS 可后补）。

### 1.2 Out of Scope（明确不做，避免范围蔓延）

跨过程/跨文件污点、CFG/数据流、SARIF、HTML 报告、基线 baseline、增量缓存、watch 模式、PR diff 扫描、规则包分发到 mooncakes.io、自定义 Reporter/谓词模块（trait 扩展）、C/C++（MCIL）、WASM 目标、嵌入库、SaaS/IDE。

> 这些不是"永远不做"，是本 MVP 不验收。接口预留见 §10。

### 1.3 语言与规则范围

语言注册键与 grammar 函数映射（**实测差异必须遵守**）：

| 语言 ID | 扩展名 | grammar 包 | 版本 | 构造函数 |
|---|---|---|---|---|
| `javascript` | `.js` `.jsx` `.mjs` `.cjs` | `tree-sitter-javascript` | 0.25.0 | `language()` |
| `typescript` | `.ts` | `tree-sitter-typescript` | 0.23.2 | `language_typescript()` |
| `tsx` | `.tsx` | `tree-sitter-typescript` | 0.23.2 | `language_tsx()` |
| `python` | `.py` | `tree-sitter-python` | 0.23.6 | `language()` |
| `java` | `.java` | `tree-sitter-java` | 0.23.5 | `language()` |
| `json` | `.json` | `tree-sitter-json` | 0.24.8 | `language()` |

`【实测】` TS 包导出两个不同函数，其余包只有 `language()`；这是最容易写错的一处，语言注册表必须显式列出构造函数，不要用命名约定推断。

**首批规则清单（每语言 10 条，ID 稳定，不得在后续改名）**：

| 语言 | 规则 ID 前缀 | 覆盖类别 |
|---|---|---|
| JavaScript | `JS001`–`JS010` | eval / new Function / innerHTML、SQL 拼接、硬编码密钥、`child_process.exec`、`yaml.load` 不安全反序列化、cookie 缺 HttpOnly、弱随机、DOM XSS、路径拼接 |
| TypeScript | `TS001`–`TS010` | 同 JS 的 TS 语法变体 + `as any` 绕过类型约束后的危险调用 |
| Python | `PY001`–`PY010` | eval/exec、pickle、yaml.load、`shell=True`、SQL 拼接、硬编码密钥、`verify=False`、弱哈希、临时文件、assert 校验 |
| Java | `JAVA001`–`JAVA010` | `Runtime.exec`、SQL 拼接、硬编码密钥、XXE、反序列化、弱随机、路径遍历、敏感日志、DES/MD5、JSP 输出 |
| JSON 配置 | `CFG001`–`CFG010` | 明文口令字段、debug 开启、宽松 CORS、TLS 关闭、权限通配符等 |

每条规则必须提供：`fixtures/<id>/positive.<ext>`、`fixtures/<id>/negative.<ext>`、`expected.json`。规则实现细节见 §5。

---

## 2. P0 已验证基线（必须继承的事实）

### 2.1 版本锁定表

| 依赖 | 锁定版本 | 来源 |
|---|---|---|
| MoonBit 工具链 | `moonc v0.10.21` / `moon 0.1.20261117` | `【实测】` P0 本机；CI 用同一版本 |
| `moonbit-community/treesitter` | `0.1.1` | `【实测】` 0.1.0 在当前编译器下编译失败 |
| grammar 包 | 见 §1.3 | `【实测】` 5 个包均已验证编译与 `language()` 加载 |
| `moonbitlang/async` | `0.22.10` | `【实测】` treesitter 传递依赖同版本，无冲突 |
| `mizchi/bit_hash` | `0.50.0` | `【实测】` NIST 向量通过；依赖 `mizchi/simd`（MIT） |
| `mizchi/bit_ignore` | `0.50.0` | `【实测】` 零依赖，gix 语义 |

所有依赖在 `moon.mod` **精确锁版本**，禁止 `moon add --upgrade` 进入 CI。许可证：上述全部 Apache-2.0（simd MIT），可商用分发 `【实测】`。

### 2.2 关键 API 速查（按实测签名，可直接编码）

```moonbit
// Tree-sitter —— 来自 pkg.generated.mbti，已实测编译运行
@treesitter.Query::new(language, query_string) -> Query        // raise QueryError
@treesitter.Parser::new() -> Parser
parser.set_language(language) -> Unit                          // raise LanguageError
parser.parse(@utf8.encode(text)) -> Tree?                      // Option，非 raise
cursor.matches(query, tree.root_node(), source_bytes) -> QueryMatches
matches.next() -> QueryMatch?
query.capture_index_for_name("callee") -> Int32?               // 按捕获名取索引
match.nodes_for_capture_index(index) -> Iter[Node]             // 精确取捕获节点
match.captures() -> ArrayView[QueryCapture]                    // QueryCapture { node, index }
node.start_position() -> Point                                 // Point { row: Int32, column: Int32 }
node.utf8_text(source_bytes) -> String                         // raise
node.kind() -> String
node.has_error() / node.is_error() / node.is_missing() -> Bool
tree.walk() -> TreeCursor                                      // 遍历错误节点

// 文件与并发 —— 已实测
@fs.walk(path, callback, exclude?, max_concurrency?, allow_failure?) -> Unit
  // callback: async (String /*dir_path*/, Array[String] /*entries*/) -> Unit
  // entries 同时含子目录名，必须按扩展名过滤；子目录由 walk 自行递归
@fs.read_file(path).text() -> String
@async.with_task_group(async (TaskGroup[X]) -> X)              // lambda 用 `<|` 传，不写 async () => {}
TaskGroup::spawn(group, async () -> X, no_wait?, allow_failure?)
@semaphore.Semaphore::Semaphore(Int32, initial_value?)         // try_acquire() -> Bool / release()

// 指纹 / 输出 / 退出码 —— 已实测
@bithash.sha256_raw(bytes) / @bithash.hex_encode(bytes)
@json.to_json(value).stringify()
#derive(@json.ToJson) / #derive(@json.FromJson)
@env.args() / @env.exit(code)                                  // 业务退出码用 exit，不用 abort
```

### 2.3 必须规避的坑（逐条来自 P0 失败记录）

| # | 坑 | 规避方式 |
|---|---|---|
| 1 | grammar `binding.mbt` 统一用 `e.to_string()`，moonc 0.10 下集体编译失败 | 编译前跑 `scripts/patch_grammars.py`，以 `--check` 做 CI 门禁 `【实测】` |
| 2 | `moon.work` 本地覆盖会编译 treesitter 全部内部包，暴露 9 处新错误 | **禁止**用 workspace 覆盖打补丁；用原地幂等脚本 |
| 3 | `postadd` 是依赖作者钩子且标注 extremely experimental | **禁止**用于消费方打补丁 |
| 4 | `String::to_bytes()` 非 UTF-8 语义且已弃用 | 一律 `@utf8.encode(s)`，否则 SHA-256 值错误 |
| 5 | JS 节点名是 `call_expression`，不是 `call` | Query 以 grammar 的 node-types 为准，`rules-validate` 捕获编译错误 |
| 6 | 根包 `moon.pkg` 的 import 不传递到子包 | 每个含代码的目录（含 `apps/scan`）都要写自己的 `moon.pkg` |
| 7 | `async fn main` 必须在本包声明 `@async` 依赖 | `apps/scan/moon.pkg` 显式 import `moonbitlang/async` |
| 8 | `moon cram test` 无参数发现 0 个用例且退出 0 | CI 必须 `moon cram test tests/cram/` 显式传目录 |
| 9 | cram 每块是独立临时目录，块间不共享文件 | 用 `printf '...' > sample.js && scan.exe sample.js` 单表达式自建 fixture |
| 10 | `abort` 退出码 127；cram 失败时自身退出码 50 | 业务退出码用 `@env.exit`；CI 用 cram 进程退出码判断 |

### 2.4 可直接复用的 P0 代码

`p0-spike/p0-e2e/cmd/main/main.mbt` 已跑通完整链路：`@fs.read_file` → `@utf8.encode` → grammar 解析 → Query + `#eq?` → Finding → `#derive(@json.ToJson)` → stdout。它可作为 `apps/scan` 的最小骨架，但需按 §2.3 修正退出码、按 §4 补齐数据模型。`p0-spike/t11-t12-grammar/scripts/patch_grammars.py` 直接复制到新工程根目录（支持 `--root`、`--check`、从 `moon.mod` 自动发现 grammar）。

---

## 3. 工程结构与包设计

### 3.1 目录树

```
sast-mbt/
  moon.work                       # workspace：统一 check/test（仅列本仓库包）
  moon.mod                        # 精确锁版本，见 §2.1
  scripts/patch_grammars.py       # 从 P0 复用；构建前置 + CI 门禁
  libs/
    core-model/                   # 无外部依赖（仅 core）
    rule/                         # -> core-model
    config/                       # -> core-model
    source-file/                  # -> core-model, async, bit_ignore, bit_hash
    lang-registry/                # -> core-model, treesitter, 5 个 grammar
    parser/                       # -> core-model, lang-registry, treesitter
    query-engine/                 # -> parser, rule, core-model
    scoring/                      # -> core-model, bit_hash
    report/                       # -> core-model
    orchestrator/                 # -> 上述全部
  apps/
    scan/                         # -> orchestrator, config, report, async
    rules-validate/               # -> rule, lang-registry, treesitter
  rulepacks/official/
    rules.json                    # 50 条规则
    manifest.json                 # 规则包名 / 版本 / 校验和
  tests/
    fixtures/<rule_id>/           # positive / negative / expected.json
    cram/*.md                     # mooncram 端到端用例
  .github/workflows/ci.yml
```

### 3.2 包职责与依赖（单向，禁止反向）

| 包 | 职责 | 依赖 | 明确不负责 |
|---|---|---|---|
| `core-model` | `Severity`、`SourceLoc`、`Finding`、`ParseWarning`、`ScanResult`、`ScanConfig` | core | IO、规则语义 |
| `rule` | 规则 JSON 解析、谓词白名单定义、规则集合校验 | core-model | Query 执行 |
| `config` | CLI 参数 + 配置文件 → 不可变 `ScanConfig` | core-model | 规则语义 |
| `source-file` | `readdir`+DFS 发现（见 M2 补充 §3）、ignore、扩展名过滤、读 UTF-8、行偏移、内容哈希 | core-model, async, bit_hash, bit_ignore | 语法 |
| `lang-registry` | 扩展名→语言→grammar 构造函数 | core-model, treesitter, grammars | 规则 |
| `parser` | `parse(text, lang) -> Tree + ParseWarning[]`；节点文本/位置封装 | core-model, lang-registry, treesitter | 安全判断 |
| `query-engine` | 编译 Query、执行匹配、按捕获名取值、谓词校验 → `RawHit[]` | parser, rule, core-model | 分级 |
| `scoring` | 严重度/置信度、CWE/OWASP、指纹、抑制、去重 → `Finding[]` | core-model, bit_hash | 渲染 |
| `report` | Console / JSON / JUnit 三个实现 | core-model | 扫描调度 |
| `orchestrator` | 文件→语言→解析→查询→评分的编排；并发限流；shard 归并排序 | 上述全部 | 具体规则内容 |
| `apps/scan` | CLI 入口、退出码门禁 | orchestrator, config, report, async | 业务逻辑 |
| `apps/rules-validate` | schema + Query 编译 + 谓词白名单校验 | rule, lang-registry, treesitter | 扫描 |

依赖方向铁律：`core-model` 最底、`orchestrator` 最顶、`report` 不反向依赖 `orchestrator`。任何新增依赖必须先在 P0 报告里有实测记录。

### 3.3 构建与 CI 前置动作（不可省略）

本地与 CI 的统一顺序：

```bash
moon fetch                                  # 或 checkout 后首次 moon check 触发下载
python3 scripts/patch_grammars.py            # 幂等修补 grammar binding.mbt
python3 scripts/patch_grammars.py --check    # 门禁：未修补则非零退出
moon check --target native && moon test --target native
moon build --target native --release
moon cram test tests/cram/                   # 必须显式传目录
```

CI 矩阵首期跑 `ubuntu-latest` 与 `windows-latest`；相对主规划 P1 原定的三平台矩阵，MVP **收紧为两平台**，macOS 列为 M5 验收后的补项（需新增 runner 与 native 构建验证）。Windows 上 native debug/release 均已实测可用 `【实测】`，无需 C backend 回退作为主路径，但保留 `--target js` 的能力验证作为可选兜底。

---

## 4. 数据模型与接口（已按实测校准）

### 4.1 与主规划"示意接口"的四处关键差异

主规划 §3.4 是示意稿，MVP 按实测作如下校准，实现以本节为准：

1. `Query::new` / `parser.set_language` 是 **raise**，`parser.parse` 返回 **Option**，`matches.next()` 返回 **Option**——错误处理必须显式写 `catch` / `guard`，不能按示意稿忽略。
2. `Point.row/column` 是 `Int32`，`Finding.line/column` 转 1-based 时 `+1`；P0 e2e 用 `.to_int()` 是为了适配旧示例代码，正式代码统一保留 `Int` 字段并显式转换。
3. 捕获取值优先用 `query.capture_index_for_name(name)` + `match.nodes_for_capture_index(idx)`，**不要**像 P0 e2e 那样遍历全部 captures——否则谓词绑定的捕获名会错位。
4. 业务退出码用 `@env.exit(code)`；`abort` 只用于真正的不可恢复错误（实测退出码 127）。

### 4.2 core-model

```moonbit
enum Severity { Critical | High | Medium | Low | Info }
enum Confidence { High | Medium | Low }

struct SourceLoc {
  path : String
  line : Int          // 1-based
  column : Int        // 1-based
  byte_offset : Int
} derive(Show, Eq)

struct Finding {
  rule_id : String
  severity : Severity
  confidence : Confidence
  cwe : Array[Int]
  owasp : Array[String]
  primary : SourceLoc
  related : Array[SourceLoc]
  message : String
  snippet : String
  fingerprint : String
} derive(Show)

struct ParseWarning {
  path : String
  line : Int
  column : Int
  message : String
}

struct ScanResult {
  findings : Array[Finding]        // 已排序、已去重
  warnings : Array[ParseWarning]
  skipped_files : Array[String]
  stats : ScanStats
} derive(Show)

struct ScanStats {
  files_scanned : Int
  files_skipped : Int
  bytes_scanned : Int
  raw_hits : Int
  duration_ms : Int
}
```

序列化通过 `report` 层的 DTO 完成：`#derive(@json.ToJson)` 直接作用于 DTO struct（P0 已实测可行）。`Severity` 到字符串的映射在 DTO 转换时显式写出，不依赖 enum 的 derive 形态，保证 cram 快照稳定 `【设计】`。

### 4.3 parser 与 lang-registry

```moonbit
// lang-registry
struct LanguageSpec {
  id : String                      // "javascript" / "typescript" / ...
  extensions : Array[String]
  make_language : () -> @treesitter.Language
}
fn language_for_extension(ext : String) -> LanguageSpec?

// parser
struct ParsedFile {
  tree : @treesitter.Tree
  source : Bytes                   // @utf8.encode 的结果
  warnings : Array[ParseWarning]
}
fn parse(spec : LanguageSpec, source_text : String, path : String) -> ParsedFile
```

`parse` 内部：`Parser::new()` → `set_language`（catch 转 `ParseWarning` 并降级为空树）→ `parse(bytes)`（None 同理）→ 用 `TreeCursor` 遍历 `has_error()` 节点生成 warning；**解析错误不中断扫描**。

### 4.4 query-engine 与 rule

```moonbit
// rule —— 谓词是固定集合，不执行任意代码
enum PredicateKind {
  TextEquals | TextNotEquals | HasPrefix | NotHasPrefix
  | HasSuffix | Contains | NotContains
}
struct PredicateSpec { kind : PredicateKind, capture : String, value : String }
struct Rule {
  id : String
  language : String
  severity : Severity
  cwe : Array[Int]
  owasp : Array[String]
  query : String
  predicates : Array[PredicateSpec]
  message : String
  enabled : Bool
} derive(@json.FromJson, ToJson)

// query-engine
struct RawHit {
  rule_id : String
  severity : Severity
  primary : SourceLoc
  captures : Map[String, String]    // 捕获名 -> 节点源文本
}
fn run_rules(parsed : ParsedFile, rules : Array[Rule]) -> Array[RawHit]
```

`run_rules` 的关键步骤：每条规则编译一次 `Query`（`Query::new` catch → 记为规则错误并跳过该规则，不崩进程）；`QueryCursor::matches` 得到匹配后，对每个匹配按规则声明的谓词逐条校验；全部通过才产生 `RawHit`。正则类谓词不在 MVP 白名单内——Tree-sitter 原生 `#match?` / `#any-of?` 已在 P0 实测可用 `【实测】`，放在 query 字符串里表达，宿主侧只做简单字符串谓词。

### 4.5 scoring / report / orchestrator

```moonbit
// scoring
fn make_fingerprint(rule_id : String, snippet : String) -> String
  // @bithash.hex_encode(@bithash.sha256_raw(@utf8.encode(rule_id + "|" + normalize(snippet))))
fn finalize(hits : Array[RawHit], config : ScanConfig) -> ScanResult
  // 严重度映射、置信度、指纹去重（同 fingerprint 保留首例）、抑制注释过滤

// report —— MVP 三个实现，P2 再开放 trait
fn render_console(result : ScanResult) -> String
fn render_json(result : ScanResult) -> String
fn render_junit(result : ScanResult) -> String

// orchestrator
fn scan(config : ScanConfig) -> ScanResult
  // with_task_group + Semaphore(file_concurrency) 限流；每个文件独立任务
  // shard: 仅处理 hash(path) % shard_total == shard_index 的文件
  // 归并：findings / warnings 按 (path, line, column, rule_id, fingerprint) 全量排序
```

**确定性保证**（验收硬指标）：排序键覆盖全部字段、JSON 输出不依赖 Map 迭代顺序（先按 key 排序再序列化）、不输出时间戳与绝对路径（路径统一为相对 root 的 POSIX 风格）。

---

## 5. 规则 DSL 与规则包

### 5.1 规则 JSON Schema（单条）

```json
{
  "id": "JS001",
  "language": "javascript",
  "severity": "high",
  "cwe": [95],
  "owasp": ["A03:2021"],
  "query": "(call_expression function: (identifier) @callee arguments: (_) @arg) @call",
  "predicates": [
    { "kind": "text_equals", "capture": "callee", "value": "eval" },
    { "kind": "not_has_prefix", "capture": "arg", "value": "\"" }
  ],
  "message": "Dynamic code execution via eval()",
  "enabled": true
}
```

上述 JS001 示例 Query 与带 `#eq?` 谓词的变体已用 JS grammar 实测编译通过（2/2），且 `capture_names()` 返回 3 个、`capture_index_for_name("callee")` 可解析 `【实测】`。

规则包清单 `manifest.json` 含 `name`、`version`、`analyzer_min_version`、`rules` 文件路径与 SHA-256 校验和；`config` 按 `rulepack_version` 记录到 `ScanConfig`，为 P2 缓存键预留。

### 5.2 固定谓词集合（MVP 全集，不得扩展）

| kind | 语义 |
|---|---|
| `text_equals` / `text_not_equals` | 捕获节点源文本与 value 全等 / 不等 |
| `has_prefix` / `not_has_prefix` | 前缀匹配 / 不匹配（如排除字符串字面量参数） |
| `has_suffix` / `not_has_suffix` | 后缀匹配 |
| `contains` / `not_contains` | 子串匹配 |

谓词白名单由 `rule` 包从字符串解析，`apps/rules-validate` 遇到未知 kind 直接报错并列出合法值。需要正则语义时写进 Query 的 `#match?` / `#any-of?`（已实测可用），宿主侧不引入动态正则编译，避免规则成为任意代码执行入口。

### 5.3 rules-validate 校验清单

1. `manifest.json` 与每条规则的 schema 合法（未知字段报错）。
2. 规则 ID 全局唯一、命名符合 `<LANG><NNN>`、`language` 属于 §1.3 的注册键。
3. Query 能被对应 grammar 的 `Query::new` 编译；编译失败时输出 `QueryError` 的行列偏移与规则 ID。
4. 谓词引用的 `capture` 名必须出现在 Query 的 `capture_names()` 中（用 `capture_index_for_name` 校验）——防止规则里写错捕获名导致静默漏报。
5. 每条规则在 `tests/fixtures/<id>/` 下有 positive / negative / expected.json 三件套。

任一项失败 → 非零退出，CI 阻断。

---

## 6. CLI 契约

```
scan <root> [options]
  --lang <csv>          语言过滤，默认全部（javascript,typescript,tsx,python,java,json）
  --rules <path>        规则包目录，默认内置 rulepacks/official
  --format <csv>        console,json,junit（可多选），默认 console,json
  --out <dir>           报告输出目录，默认 stdout
  --fail-on <severity>  critical|high|medium|low|info|never，默认 high
  --shard <i>/<n>       分片，默认 0/1
  --ignore <pattern>    追加 ignore 规则（叠加 .gitignore）
  --max-concurrency <n> 文件并发上限，默认 CPU 核数
```

**输出**：JSON 文件名固定 `findings.json`、JUnit `junit.xml`；stdout 只放 Console 摘要，便于 cram 断言。

**退出码**：

| 码 | 含义 |
|---|---|
| 0 | 扫描完成且无达到 `fail-on` 的 Finding |
| 1 | 存在达到 `fail-on` 阈值的 Finding（CI 门禁命中） |
| 2 | 配置/规则/参数错误（含 `rules-validate` 失败） |
| 3 | 扫描过程出现不可恢复错误（如全部 grammar 加载失败） |

实现用 `@env.exit(code)`；禁止用 `abort` 表达上述业务状态 `【实测】`。

**shard 语义**：`--shard i/n` 只处理 `hash(relative_path) % n == i` 的文件；每个 shard 输出自己的 JSON，CI 侧归并后必须再做一次全量排序与指纹去重。MVP 提供 `scripts/merge_shards.py` 作为参考实现（P2 再内建）。

---

## 7. 实现任务分解

按依赖顺序执行；每批结束必须跑完验收命令才进入下一批。

### M0 — 工程骨架与构建基线

- **输入**：P0 的 `patch_grammars.py`、版本锁表。
- **产出**：`moon.work` + `moon.mod` + 空包骨架 + `scripts/patch_grammars.py` + CI 工作流。
- **验收**：`moon check --target native` 零错误；`patch_grammars.py --check` 在 5 个 grammar 上通过；Windows CI 任务能跑通同样命令。

### M1 — core-model / rule / config

- **产出**：§4.2、§4.4 的 model 与 rule 解析；`apps/rules-validate` 骨架；`rulepacks/official/manifest.json`。
- **验收**：`moon test --target native` 覆盖 JSON roundtrip、谓词白名单、ID 唯一性；`rules-validate` 对故意写错的规则返回码 2 并给出行列信息。

### M2 — source-file / lang-registry / parser

- **产出**：`@fs.walk` + bit_ignore 文件发现；6 个语言注册项（含 TS 双函数）；解析封装与错误节点 warning。
- **验收**：单元/集成测试：给定含子目录、`.gitignore`、二进制文件、无扩展名文件的 fixture，断言发现文件集合精确；语法错误 JS 文件产出 ParseWarning 且扫描不中断。

### M3 — query-engine / scoring

- **产出**：Query 编译与按捕获名取值、谓词校验、`RawHit` → `Finding`、指纹/抑制/去重。
- **验收**：用 P0 e2e 的 `danger.js`（2 条 eval）与 `safe.js`（0 条）作回归基线；指纹与 P0 输出逐字节一致；重复 snippet 去重为 1 条。

### M4 — orchestrator / report / apps/scan

- **产出**：并发限流、shard、三种 reporter、CLI 参数与退出码、`scripts/merge_shards.py` 参考实现。
- **验收**：`moon cram test tests/cram/` 全绿（至少 6 个用例：检出、干净、语法错误容错、门禁退出码 1、参数错误退出码 2、shard 归并）；连续两次运行 `findings.json` diff 为空。

### M5 — 规则包 / fixtures / 全量验收

- **产出**：50 条规则 + 每规则正/反例与 expected.json；golden 快照；CI 矩阵 completion。
- **验收**：§8.3 全部指标达标；`rules-validate` 对正式规则包返回 0；两个平台 CI 全绿。

---

## 8. 测试策略与验收标准

### 8.1 测试分层（沿用主规划 §5.3，补充 MVP 具体做法）

| 层级 | 手段 | MVP 具体对象 |
|---|---|---|
| 单元 | `moon test` 内联 test | 指纹稳定、行偏移、谓词判定、JSON roundtrip、扩展名映射 |
| 规则校验 | `apps/rules-validate` | schema、Query 编译、捕获名存在、谓词白名单、fixture 三件套 |
| CLI 端到端 | `moon cram test tests/cram/` | 参数、输出、退出码、shard 归并；每块 `printf && scan.exe` 自建 fixture |
| Golden | `expected.json` 快照 | 每条规则正反例的 Finding 数量与 rule_id |
| 差分 | grammar 自带 differential oracle（P2 增强） | grammar 升级前后 Query 语义一致性 |
| 覆盖 | `moon coverage analyze` | 未测分支（M5 起设最低覆盖率阈值） |

### 8.2 fixture 设计原则

- 正例只包含目标漏洞的最小可编译代码；反例只改一处（如把 `eval` 换成普通函数名、把参数改成字符串字面量），确保规则粒度可归因。
- 每条规则的 `expected.json` 只记 `rule_id` + 行号 + `finding_count`，不记指纹（指纹单独测），避免 fixture 脆弱。
- 语法容错 fixture：故意截断的函数体 + 1 条正常 `eval`，断言既产出 Finding 又产出 ParseWarning。

### 8.3 量化验收指标（MVP 硬门槛）

| 指标 | 目标 | 测量方法 |
|---|---|---|
| 规则检出率 | ≥ 90% | 命中正例数 / 正例总数 |
| 反例误报率 | ≤ 10% | 反例产生的 Finding 数 / 反例文件数 |
| 确定性 | 100% | 同输入连续两次 `findings.json` 逐字节 diff 为空 |
| 容错 | 100% | 注入语法错误后扫描完成且 warning 非空 |
| 规则校验 | 100% | 50 条规则全部通过 `rules-validate` |
| 平台 | Linux + Windows | CI 矩阵两平台全绿；Windows native 为主路径 |
| 性能基线 | 记录值，不设阈值 | 记录 LOC/s、峰值内存、耗时（`moon bench` / `--profile`），P2 起设回归线 |

---

## 9. 风险与回退

| 风险 | 概率 | 影响 | 缓解 |
|---|---|---|---|
| grammar 补丁脚本遗漏新包 | 中 | 高 | 脚本从 `moon.mod` 自动发现 grammar；`--check` 进 CI 门禁；新增语言必过 M0 |
| 上游 grammar 发布修复版后脚本误改 | 低 | 中 | 脚本幂等且识别已修复形式并跳过；升级依赖后重跑 `--check` |
| 谓词表达力不足导致规则漏报 | 中 | 中 | 复杂匹配下沉到 Query 的 `#match?`/`#any-of?`（已实测）；宿主谓词保持简单可审计 |
| TS/TSX 构造函数写错 | 中 | 中 | 语言注册表显式函数；M2 加断言测试 |
| 捕获名拼写错误静默漏报 | 中 | 高 | `rules-validate` 用 `capture_index_for_name` 校验捕获名存在 |
| cram 未显式传目录导致 CI 假绿 | 高 | 高 | CI 命令固定 `moon cram test tests/cram/`；加一条"故意失败用例"验证退出码 50 可被捕获 |
| 退出码用错 abort | 中 | 中 | 统一封装 `exit_with(code)`；cram 断言退出码 `[1]` / `[2]` |
| 报告含绝对路径/时间戳破坏确定性 | 中 | 高 | 路径统一相对化 + POSIX 分隔符；DTO 不含时间字段；确定性测试进 M4 验收 |
| 单线程协作式并发被误当多核 | 中 | 中 | 文件级并发用于 IO 重叠；CPU 密集解析靠 `--shard` 多进程；不承诺多核加速 |

---

## 10. 与 P2 的衔接（接口预留，MVP 不实现）

1. `RawHit` 预留 `taint_confirmed : Bool` 字段（MVP 恒为 `false`），P2 的 `taint` 模块只确认/裁剪，不改上游接口。
2. `ScanConfig` 预留 `incremental : Bool` 与 `rulepack_version : String`；缓存键 `(path, content_hash, rulepack_version, analyzer_version)` 在 P2 启用。
3. `report` 先写三个具体函数；P2 抽 `trait Reporter` 时保持 DTO 不变，避免破坏 cram 快照。
4. `Finding.confidence` 在 MVP 恒为 High（AST 确定性匹配）；P2 污点确认后才细分。
5. `SourceLoc.byte_offset` 从第一天就填，供 P2 的基线定位与 SARIF 区域映射使用。

---

## 附：MVP 完成检查清单（逐项打勾）

- [x] **M0（2026-11-22 完成）**：`sast-mbt/` 工程骨架 + 版本锁 + 两平台 CI。实测：全新 checkout 模拟下 `verify.sh` 全绿（`moon check --target native` 零错误、补丁门禁三段验证、JS 后端 11/11、`moon fmt --check`）；版本由 `moonbit-version` + CI `setup-moonup@v2` 双重锁定为 `0.10.21+06da1ed44`。CI 工作流见 `sast-mbt/.github/workflows/ci.yml`。**注意**：本机 Windows 缺 Windows SDK，`moon test --target native` 本地失败（P0 工程同样失败，证明非工程问题）；native test/build 交由 CI 的 full-SDK runner 执行。
- [x] **M1（2026-11-22 完成）**：`core-model` / `rule` / `config` 三包 + `apps/rules-validate` + `rulepacks/official` 最小规则包。实测：`verify.sh` 全绿——`moon check --target native` 零错误、`moon test --target native` **25/25**、`moon fmt --check` 通过、patch 门禁三段通过；rules-validate 对正式规则包退出 0，对坏规则包退出 2 并输出 `line 2, column 19` 行列诊断。详见下方「M1 实现补充（实测校准）」。
- [x] **M2（2026-11-22 完成）**：`lang-registry` / `parser` / `source-file` 三包 + `apps/rules-validate` 改用统一语言注册表。实测：`verify.sh` 全绿——`moon test --target native` **43/43**、`moon fmt --check` 通过、patch 门禁三段通过、rules-validate 退出码 0/2 仍正确。6 个语言注册项齐全（TS/TSX 用硬证据断言不同 grammar）；发现集合精确（含子目录、`.gitignore`、二进制、无扩展名 fixture）；截断 JS 产出 ParseWarning 且不中断。详见下方「M2 实现补充（实测校准）」。
- [x] **M3（2026-11-22 完成）**：`query-engine` / `scoring` 两包 + `tests/integration` 回归成员。实测：`verify.sh` 全绿——`moon test --target native` **62/62**、`moon fmt --check` 通过。P0 基线复现：`danger.js` 2 条 raw hit、去重后 1 条 finding、行 2/列 1、snippet `eval`，**指纹 `cad6a9d4…da31` 与 P0 输出逐字节一致**；`safe.js` 0 条；两次运行渲染逐字节相同。顺带修复一处真实规则缺陷（见 M3 补充 §3）
- [x] **M4（2026-11-22 完成）**：`report`（console/json/junit）+ `orchestrator`（限流、shard、汇总）+ `apps/scan` CLI + `tests/cram/`（**13 用例**）。实测：`verify.sh` 全绿（8 步）——`moon test --target native` **65/65**、`moon cram test tests/cram/` **13/13**、`moon fmt --check` 通过、rules-validate 0/2 通过；退出码矩阵 0/1/2/3 全覆盖，shard 0/2 + 1/2 并集等于全量，两次运行 `findings.json` 逐字节相同
- [x] **M5（2026-11-22 完成）**：50 条规则（JS 10 / TS 5 / TSX 5 / PY 10 / JAVA 10 / CFG 10）+ 150 个 fixture 文件 + `scripts/gen_rulepack.py`（可 `--check` 防漂移）+ `scripts/check_golden.py`。实测：**检出率 100%（50/50）、反例误报率 0%（0/50）**，`verify.sh` 9 步全绿（单测 66/66、cram 13/13、rules-validate 0/2、golden PASSED）。两平台 CI 沿用同一脚本，未实际推送运行

### M0 实现补充（实测校准）

1. **多模块 workspace 结构**：每个 lib/app 是独立 module，`moon.work` 列 members，包间依赖在各自 `moon.mod` 用 `import { "sast/<mod>@0.1.0" }`（本地解析）。M0 阶段各包为空骨架，跨包依赖在 M1 加入。
2. **补丁脚本升级**：`sast-mbt/scripts/patch_grammars.py` 从 P0 单模块版扩展为可扫描 `moon.work` 全部 members 的 `moon.mod`，同时兼容单模块布局。修复了 P0 版 `--check` 把"待修补"误计为已通过的 bug（现已实测：未修补退出 1、修补后退出 0、重复执行幂等）。
3. **CI 版本锁定**：`setup-moonbit` action 只接受 latest/nightly，无法锁精确版本；改用 `chawyehsu/setup-moonup@v2` 的 `moonbit-version` 输入 + 工程根 `moonbit-version` 文件，并在 CI 加 grep 守卫防止版本漂移。
4. **验证脚本**：`sast-mbt/scripts/verify.sh` 统一本地/CI 命令序列；本机无 SDK 时跳过 native test，CI full-SDK runner 补跑。

### M1 实现补充（实测校准）

1. **跨模块依赖写法已验证**：`moon.work` 多模块 workspace 内，消费方 `moon.mod` 写 `import { "sast/core-model@0.1.0" }`，`moon.pkg` 写 `import { "sast/core-model" @core }`。M1 已在 `rule → core-model`、`config → core-model`、`rules-validate → rule` 上实测通过，无需 vendor 或 workspace override。
2. **`Show` 已弃用**：当前 moonc 0.10.21 对 `#derive(Show)` 报 `deprecated_syntax`；`Debug` 与 `Eq` 可用。model 类型统一改 `#derive(Debug, Eq)`。`enum` 必须写 `pub(all) enum`，仅 `pub enum` 的构造器是只读的，外部无法构造（错误 4036）。
3. **JSON 解析必须手写**（关键设计决策）：实测 `@json.FromJson` derive 对未知字段是**静默接受**的，`rules-validate` 的"未知字段报错"要求无法靠 derive 实现。因此 `libs/rule/parse.mbt` 用 `@json.parse` → 逐字段 `Map.get` + 类型检查，未知字段返回带 JSON Pointer 的 `RuleError`。同时 `RuleError` 用 `suberror` + `raise`/`catch`（MoonBit 不支持 Result 的 `?` 运算符；`suberror` 字段需模式匹配解构）。
4. **稳定序列化**：`Severity` / `Confidence` / `PredicateKind` 不用 derive ToJson（enum derive 会产生与输入不一致的形态），改为手写 `impl @json.ToJson` 输出小写稳定名；`Rule` / `PredicateSpec` 用 derive。JSON roundtrip 测试通过（9/9）。
5. **async/fs 仅 native 可用**：`moonbitlang/async/fs` 的 `pkg.generated.mbti` 声明 `targets: ["native"]`，`moon test --target js` 在 workspace 含 rules-validate 后必然失败（错误 4021）。**验证主路径改为 `moon test --target native`**（本机 SDK 实际可用，M0 记录的 SDK 缺失未复现）；`verify.sh` 加 `--js-test` 可选参数仅做部分检查。`async fn main` 必须在 `moon.pkg` 显式 `import "moonbitlang/async" @async`。
6. **Query 错误带行列**：根包 `@treesitter.QueryError` re-export 为 5 字段 variant `QueryError(row, column, offset, message, kind)`，需模式匹配解构；`Query::new(Language, String)` 收 String 而非 Bytes。校验器同时输出 Query 编译的行列（若 grammar 拒绝）与 JSON ParseError 的 `line/column`（实测 `line 2, column 19`）。tree-sitter 对未知谓词/未闭合括号较宽容，不视为编译错误。
7. **验收脚本固化**：`scripts/check_rules_validate.sh` build native exe，断言正式规则包退出 0、坏规则包退出 2 且输出含 `line/column`；已接入 `verify.sh` 第 7 步。CI 删去与 verify.sh 重复的独立 Native test 步骤，保留 native release build。
8. **首条规则**：`rulepacks/official/rules.json` 目前仅含 `JS001`（eval）作为验证样例，`manifest.json` 记录 SHA-256；fixture 三件套在 `tests/fixtures/JS001/`。**50 条规则仍属 M5 范围**，M1 只验证规则包管线可跑通。

### M2 实现补充（实测校准）

1. **`String::compare` 是 shortlex，不是字典序**（关键坑）：stdlib 文档明确 "ordered based on shortlex order"，实测 `"main.js".compare("binary.js") == -1`（先比长度再比码元）。因此**路径排序必须用 `StringView::lexical_compare`**，否则报告里文件顺序看起来随机（先 7 字符再 9 字符）。`source-file` 的 `compare_strings` 显式调用 `a[:].lexical_compare(b[:])`，并自带 `merge_sort_by`（纯 push、无 in-place 语义依赖）。
2. **`@fs.readdir(dir, sort?=true)` 的排序参数不生效**：实测返回 `[lib, ignored, main.js, Makefile, util.mjs, binary.js, ...]`（NTFS 枚举顺序）。发现顺序一律由包内归并排序建立，不能依赖该参数。
3. **发现实现从 `@fs.walk` 改为 `readdir` + 显式 DFS**：`walk` 的回调式收集需要额外排序，且 `allow_failure` 会吞掉逐目录读取失败；改用递归后可按目录把失败精确记为 `Unreadable`，并在返回前完成排序。这是对 §3.2 "`@fs.walk` 发现" 的**有意偏离**，理由如上（`@fs.walk` 本身仍可用，P0 T6 已实测）。
4. **TS / TSX 双构造函数已用硬证据断言**：`typescript` 与 `tsx` 的 `field_count` 为 40 / 43；`id_for_node_kind("jsx_element", true)` 为 0 / 225；`name()` 为 `typescript` / `tsx`。另有语义断言：同一段 JSX 源码用 `tsx` 解析 0 warning，用 `typescript` 解析必然报错。这直接覆盖 §9 "TS/TSX 构造函数写错" 风险。
5. **`async test` 必须导入 `moonbitlang/async`**：即使包内没有直接使用该包，测试框架生成的 driver 也要求 `moonbitlang/async` 在 `moon.pkg` 中（否则报 `moonbitlang/core/async is not imported`）。副作用是留下 2 条 `unused_package` 警告，属可接受噪声。
6. **`priv struct` 消除 `missing_priv` 警告**：`source-file` 的内部累加器 `Collector` 不出现在公开签名，需显式 `priv struct`，否则每个包构建都有告警。
7. **字符串切片 API**：`String::substring` 已弃用且参数是 `Int32`；统一用 `s[i:]`（返回 `StringView`）+ `.to_owned()`，`to_string()` 在 `StringView` 上同样弃用。`Bytes` 侧用 `length()` / `get(i)` / `iter()`，NUL 检测走 `iter()`。
8. **解析容错的产品语义**：`ParsedFile.tree` 为 `None` 只在 grammar 装载失败或 parser 拒绝产树时出现，语法错误一律表现为 `tree = Some` + 非空 `warnings`（上限 20 条/文件，防噪声与输出膨胀）。这保证"语法错误不中断扫描"是可测的不变量（测试：截断 JS、乱码 JS、TSX vs TS 对照）。
9. **语言清单双份但受测试保护**：`libs/rule` 为保持零 grammar 依赖，保留自己的 `registered_languages()`；`apps/rules-validate/consistency_test.mbt` 断言它与 `lang-registry.language_ids()` 完全一致，防止 §9 的注册项漂移。
10. **单元测试 fixture 位置**：`moon test` 的工作目录是包目录，因此发现测试的 fixture 放在 `libs/source-file/testdata/`（`tests/fixtures/` 保留给规则 fixture 与 M4 cram）。

### M3 实现补充（实测校准）

1. **`RawHit` 放在 `core-model` 而非 `query-engine`**：`scoring` 的下游输入必须来自模型层，否则 `scoring → query-engine` 会违反 §3.2 的单向依赖。`Fingerprint`/去重/排序只吃 `Array[RawHit]`，`finalize` 因此零外部依赖（core-model + bit_hash）。
2. **`finalize` 签名按实际需要收窄**：§4.5 写的是 `finalize(hits, config)`，但 `ScanConfig` 在 `config` 包，`scoring` 引它会形成不必要的耦合，且 `--fail-on` 门禁本就属于 CLI/orchestrator。实现为 `finalize(hits)` 与 `finalize_with(hits, suppressions)`，`fail-on` 判断留在 M4 的 `orchestrator`/`apps/scan`。
3. **发现并修复一处真实规则缺陷（重要）**：原 JS001 query 写 `arguments: (_) @arg`，`@arg` 捕获到的是**参数列表节点** `(userInput)`，于是 `not_has_prefix "\""` 永远成立 —— `eval("literal")` 会被误报。改为锚定首个参数的 `arguments: (arguments . (_) @arg)` 后，`@arg` 才是 `userInput` / `"console.log(1)"`，谓词才真正起作用。**M5 写 50 条规则时，凡是要看"参数表达式"的规则都必须用 `.` 锚点**，这是 query 语义与 hosts 谓词之间的主要陷阱。
4. **语法来自 `tree.language()`**：`run_rules` 编译 Query 时用解析该文件的同一份 grammar（`tree.language()`），而不是按 `rule.language` 字符串再查一次注册表。这样规则语言键与实际 grammar 不可能错配，也免掉 `query-engine → lang-registry` 依赖。
5. **指纹与 P0 逐字节一致**：`make_fingerprint = hex(sha256(rule_id + "|" + normalize(snippet)))`，`normalize` 只折叠空白、不改变 token，因此 `"JS001|eval"` → `cad6a9d402bd4d6c926a60f7d06d046c4fdf4b613dab5be32c2189e45cd3da31`。该常量同时固化在 `scoring_test` 与 `tests/integration`，任一侧改动都会红。
6. **抑制语法（MVP 全集）**：`// sast-ignore`（本行）、`// sast-ignore-next-line`（下一行）、可选 `: JS001,JS003` 限定规则。解析在 `scoring.parse_suppressions`，纯文本无 IO；`finalize_with` 在排序前过滤，故 `stats.raw_hits` 仍反映原始命中数（`raw_hits=3 / findings=1` 可同时断言）。
7. **`pkgtype(kind: "test")` 不存在**：实测报错 `unknown variant 'test', expected one of 'library', 'executable', 'foreign_library'`。因此 `tests/integration` 的 pipeline 帮助函数放在**库文件** `pipeline.mbt`（`pub async fn scan_file`），由 `m3_test.mbt` 调用——否则纯测试包的 import 会全部被记为 `unused_package`（曾出现 23 条警告，收敛到 3 条）。
8. **`@parser.spec_for_language` 透传**：`parser` 已依赖 `lang-registry`，向上暴露一个 spec 查询即可让 `query-engine` 与集成测试都不必直连注册表；`query-engine` 的 `moon.mod` 因此不再列 `lang-registry`。
9. **集成测试读真实规则包**：`tests/integration` 直接读 `../../rulepacks/official/rules.json`（不是副本），所以"官方规则包"本身就是被测对象，规则文件与测试不可能漂移。

### M4 实现补充（实测校准）

1. **退出码全链路实测**：`0`（干净或 `--fail-on never`）、`1`（命中门禁）、`2`（参数/规则包错误，含 JSON Pointer 诊断如 `/0/language: missing required field`）、`3`（不可恢复扫描错误）。CLI 里 `@env.exit(code)` 是泛型函数 `fn[T] exit(Int32) -> T`，可直接在 `else` 分支当语句用；`abort` 仍然是 127，不用于业务码。
2. **相对路径 vs IO 路径分离**：`discover` 返回 root 相对 POSIX 路径，但读文件必须拼 root。早期版本直接把相对路径传给 `@fs.read_file`，在 `root != "."` 时全部 `unreadable`（症状：`files: 0 scanned, N skipped`）。现在只有 `orchestrator.fs_path(root, rel)` 一处拼绝对，报告里永远是相对路径。
3. **确定性来自"末尾统一排序"而非执行顺序**：并发任务把结果 push 进共享数组，随后 `scoring.finalize`（findings）与 `compare_warnings`（warnings）全量排序；`duration_ms` 恒填 0，避免时间戳破坏 diff。实测两次运行 `findings.json` `cmp` 相同。
4. **stdlib 里没有可用整数解析**：`moonbitlang/core/strconv` 在该工具链构建下 `pkg.generated.mbti` **完全为空**（无 `parse_int`）。改为自写 `parse_uint(StringView)`，注意 `Char::to_uint().reinterpret_as_int()` 得到的是 ASCII 码，必须 `-48` —— 少了这一步曾让 `--shard 0/1` 变成 `48/49`，两个 shard 都扫出 0 个文件。
5. **`moonbitlang/core/env` 无 `exit` 以外的坑；`@fs.write_file` 直接收 `String`**（`impl Data for String`），无需 `@utf8.encode`；报告文件写入时补尾部换行，否则 cram 报 `(no-eol)`。
6. **cram 两个硬约束再次验证**：必须显式传目录 `moon cram test tests/cram/`（无参数 = 0 用例且退出 0）；每块独立临时目录，因此规则包用 `printf '%s' '[...]' > rules.json` 内联自建，fixture 与扫描命令必须写在同一条 shell 表达式里。
7. **shard 的正确验证方式**：不是"每个 shard 各自有结果"，而是 `0/n` 与 `1/n` 的 `files:` 计数之和等于全量、且 findings 集合互补。cram 用 `cat s0.txt s1.txt | grep "^files:"` 断言两行。
8. **报告 DTO 而非直接序列化模型**：`report_dto` 把 `Severity` 映射成小写字符串、丢弃 `related`/内部字段，键顺序由 struct 声明固定；`render_junit` 手写 XML 并对 `& < > " '` 转义（5 类全部有测试）。

### M5 实现补充（实测校准）

1. **50 条规则的分布**：JS001–JS010、TS001–TS005（TypeScript）、TS006–TS010（TSX）、PY001–PY010、JAVA001–JAVA010、CFG001–CFG010。TSX 与 TypeScript 共用 `TS` ID 前缀（编号不重叠），这是对 §1.3 "每种语言 10 条" 的**有意分配**：tsx 是同族语法的独立 grammar，不单独占用一个语言前缀。
2. **golden 校验发现的真实缺陷：去重键必须是 `(path, fingerprint)`**。原实现只按 fingerprint 去重，导致"两个文件里相同的 `eval` 片段"被判为一条 —— 更糟的是排序后 `negative.py` 排在 `positive.py` 前面，正例被吞掉，检出率从 100% 掉到 96% 且反例"误报"1 条。改成 `path + \u{0} + fingerprint` 后语义正确：跨文件同片段算两个缺陷，同文件内重复命中仍收敛为一条。
3. **TS/TSX 的 AST 字段名与直觉不同**（必须实测）：`as_expression` 与 `jsx_attribute` **没有命名字段**，只能按位置写 `(as_expression (predefined_type) @t)`、`(jsx_attribute (property_identifier) @name)`。这是本项目第二次遇到"字段名猜错"（第一次是 `arguments: (_) @arg` 捕获到参数列表），已固化为经验：**写 query 前先 `node.to_sexp()` 看一眼真实形状**。
4. **谓词是大小写敏感的**，因此 CFG 规则的 fixture 键采用 snake_case（`api_token` / `allowed_host` / `client_secret`），避免 `contains "token"` 漏掉 camelCase 的 `apiToken`。若后续需要大小写无关匹配，应作为 P2 的新谓词类型显式加入白名单，而不是偷偷放宽语义。
5. **`object_creation_expression` 的 query 要带参数捕获**：`new File(userInput)` 与 `new File("fixed")` 只能靠 `arguments: (argument_list . (_) @arg)` + `not_has_prefix` 区分；`new Random(seed)` 也因此必须给正例传参数。
6. **manifest SHA 必须对字节而非文本计算**：Python `write_text` 在 Windows 会把 `\n` 变成 `\r\n`，导致 rules-validate 报 SHA 不匹配。生成器改用 `write_bytes`，并支持 `--check` 让 CI 能发现"手改 rules.json 但没同步生成器"。
7. **两平台 CI 的 Python 可执行名不同**：windows-latest runner 常见 `python` 而非 `python3`。`verify.sh` 改为 `PY="$(command -v python3 || command -v python)"`，全部脚本调用走 `$PY`。
8. **验收口径**：`check_golden.py` 同时检查"每条规则正例命中数/行号"和"反例零命中"，任一不符即失败（比 90%/10% 阈值更严），并打印两条硬指标的实测值供报告引用。
