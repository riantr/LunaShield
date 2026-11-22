# P0 Spike 实测报告：T2 / T3 / T5 / T6

> 执行日期：2026-11-22
> 执行环境：Windows 11 (MINGW64_NT-10.0-26200)、x86_64
> 工具链：`moon 0.1.20261117 (eb64713 2026-11-17)` / `moonc v0.10.21+06da1ed44 (2026-11-16)` / `moonrun 0.1.20261117`
> 结论摘要：**T2 ✅ Go、T3 ✅ Go（附版本兼容条件）、T5 ✅ Go（结论修正）、T6 ✅ Go（结论修正）**。四项风险的保守假设均可按实测结果收紧，P1 关键路径解锁。
> 补充实测（2026-11-22 同日）：**T11/T12 已关闭** —— 5 个 grammar 全部存在同类兼容问题，已用幂等补丁脚本统一修复并实测通过（§6）；**T4 已关闭** —— SHA-256 与 gitignore 均有可用库，8/8 测试三后端通过（§7）；**P0-1/P0-2 已关闭** —— 端到端 Finding 输出跑通、`moon cram test` 3/3 通过（§8–§9）。P0 全部完成。

---

## 0. 实测环境与方法

本次不是文档推演，而是在本机真实安装依赖、写代码、编译运行。所有 spike 工程保留在 `p0-spike/` 下，测试可直接复跑：

| 目录 | 对应项 | 复跑命令 |
|---|---|---|
| `p0-spike/t2-native/` | T2 | `moon build --target native && ./_build/native/debug/build/cmd/main/main.exe` |
| `p0-spike/t3-query/` | T3 | `python3 t11-t12-grammar/scripts/patch_grammars.py --root t3-query && cd t3-query && moon test --target native` |
| `p0-spike/t5-concurrency/` | T5 | 依赖已下载至 `.mooncakes/moonbitlang/async`，API 证据见 §3 |
| `p0-spike/t6-fs/` | T6 | `moon test --target native` |
| `p0-spike/t11-t12-grammar/` | T11/T12 | `python3 scripts/patch_grammars.py && python3 scripts/patch_grammars.py --check && moon test --target native` |
| `p0-spike/t4-cache-ignore/` | T4 | `moon test --target native`（亦可 `--target js` / `--target wasm-gc`） |
| `p0-spike/p0-e2e/` | P0-1/P0-2 | `python3 ../t11-t12-grammar/scripts/patch_grammars.py --root . && moon build --target native && moon cram test cram/` |

本次实测工具链版本比原规划基准（`moonc v0.10.19`）更新，为 `v0.10.21`；这本身就是 T1 的一个数据点：**一个月内小版本已迭代到 0.10.21，版本锁定策略必要**。

---

## 1. T2 — Windows native 后端

### 判定标准
能否在 Windows 上用 `--target native` 编译并运行可执行文件；若不能，是否有可用回退路径。

### 实测步骤与输出

```text
$ moon build --target native
Finished. moon: ran 30 tasks, now up to date
Artifacts:
  riantr/t2-native/cmd/main  native  ...\_build\native\debug\build\cmd\main\main.exe
EXIT=0

$ moon build --target native --release
Finished. moon: ran 31 tasks, now up to date
Artifacts:
  ...\_build\native\release\build\cmd\main\main.exe
EXIT=0

$ ./_build/native/debug/build/cmd/main/main.exe
Hello
EXIT=0

$ MOONBIT_NEW_NATIVE=1 moon build --target native --target-dir _build/newnative
Artifacts: ...\_build\newnative\native\debug\build\cmd\main\main.exe
EXIT=0
```

构建过程自动调用了 MSVC 工具链（日志出现 `正在创建库 ...main.lib 和对象 ...main.exp`），无需手工从 MSVC 环境启动终端；本机未预装 `cl.exe`/`clang-cl.exe` 到 PATH，但 moon 自行定位到了编译器。debug 与 release 产物均为 172K，默认与 `MOONBIT_NEW_NATIVE=1` 结果一致。

### 结论：**Go**

- `--target native` 在 Windows 上 **debug 与 release 均可构建并运行**，可执行文件路径由构建系统规范输出（可用于 CI 解析产物）。
- `MOONBIT_NEW_NATIVE=1` 开关在本平台不产生差异，说明当前 Windows 走的是统一可用路径。
- **应将原规划 T2 的"Windows native 仍 nightly、需回退"从高风险降为低风险**。仍建议 CI 保留 Windows 矩阵验证，但不必把 C backend / WASM 回退当作 P1 前置条件。

### 对 P1 的影响
CI 可直接使用 `moon build --target native --release` 生成 Windows 分发物；不再需要为 Windows 单列降级构建脚本。

---

## 2. T3 — Query 谓词（`#eq?` / `#match?` / `#any-of?`）

### 判定标准
纯 MoonBit Tree-sitter 是否真正支持文本谓词，以及捕获节点能否取文本做二次校验。如果不支持，P1 必须走宿主侧谓词降级方案。

### 实测发现

**（1）谓词实现存在且完整。** 在 `moonbit-community/treesitter` 包源码中确认：

- `query.mbt` 第 413–521 行：解析 `#eq?`、`#match?`、`#any-of?` 及各自的 `not-` 变体，含参数个数/类型校验和 `predicate_error` 报错。
- `query_cursor.mbt` 第 185 行起：`QueryMatch::satisfies_text_predicates` 在匹配阶段用 `TextProvider` 取捕获节点文本并逐条判定；`matches()` 在第 481 与 536 行调用它。
- `TextProvider` trait 对 `Bytes`/`BytesView` 已实现（`Bytes` 用 `node.byte_range()` 切 view），并支持回调式 `TextCallback`。
- `Node::utf8_text` / `Node::byte_range` 可用。

**（2）版本兼容问题（重要副产物）。** 首次用 `treesitter@0.1.0` + `moonc v0.10.21` 编译直接失败：

```text
Error: [4015] ...regex/error_format.mbt:51
Type Position has no method compare. (hint: did you mean Compare::compare?)
Error: [4015] ...error_format.mbt:202
Type ErrorKind has no method to_string. (hint: did you mean Show::to_string?)
```

根因是 MoonBit 0.10 起 `impl` 的方法不再自动提升为方法调用。升级到 `treesitter@0.1.1` 后该包自身已修复（源码中可见 `Compare::compare(...)`）。但 grammar 模块 `tree-sitter-json@0.24.8` 仍有同类问题：`binding.mbt:27` 的 `e.to_string()` 需改为 `Show::to_string(e)`；官方仓库当前没有更新版本（`moon add --upgrade` 提示已是 0.24.8）。

**（3）谓词功能实测。** 对 grammar 的 `binding.mbt` 打一行兼容补丁后（`sed -i 's/e\.to_string()/Show::to_string(e)/'`，仅改方法调用形式，不改语义），运行 `p0-spike/t3-query/t3_predicate_test.mbt`：

```text
Total tests: 4, passed: 4, failed: 0.
```

四个测试分别验证：
- `T3a` 无谓词查询命中 2 处（基线）
- `T3b` `#eq? @v "\"danger\""` 从 2 处过滤到 1 处
- `T3c` `#match? @v "danger"` 从 2 处过滤到 1 处
- `T3d` `#any-of?` 从 2 处过滤到 1 处

### 结论：**Go（带版本锁定条件）**

- 原规划的"谓词不可用 → 全部降级到宿主侧二次校验"假设**可以撤销**。P1 规则 DSL 可直接使用 `#eq?`/`#match?`/`#any-of?`，显著简化规则表达并减少二次校验代码。
- 但必须把 **toolchain 与包版本的兼容性** 作为 P1 的一等风险处理：`treesitter@0.1.0` 与 `moonc v0.10.21` 不兼容，必须用 `0.1.1+`；grammar 模块可能仍需小补丁。

### 对 P1 的影响与应对方案（T11/T12 已实测，见第 6 节）

1. **已落地**：用幂等脚本 `scripts/patch_grammars.py` 对 `.mooncakes` 中每个 grammar 的 `binding.mbt` 做精确一行替换，并以 `--check` 作为 CI 门禁。脚本从 `moon.mod` 自动发现依赖的 grammar，无需硬编码。5/5 grammar 实测通过。
2. **并行推进**：向 `moonbit-community/tree-sitter-*` 提 issue/PR 修正生成脚本 `tools/grammars/update.sh`，从源头消除该问题；上游修复后脚本会自动识别"已是新形式"并安全跳过。
3. **兜底**：谓词走宿主侧 `Node::utf8_text` + `re"..."` 二次校验（原保守方案，API 已验证可用），作为规则引擎通用能力保留。

> **更正**：本报告早期版本曾建议用 `moon.mod.json` 的 `scripts.postadd` 自动打补丁。经核实该建议不成立——`moon.mod.json` 已被普通工具链拒绝（须用 `moon.mod`），且 `postadd` 官方标注为 *extremely experimental*，语义是"依赖被添加后运行依赖自身的脚本"，不能保证适用于消费方给依赖源码打补丁。该方案已废弃，勿采用。

---

## 3. T5 — 并发原语与多核策略

### 判定标准
是否有 semaphore/channel；是多线程还是单线程协作式；多进程分片策略是否仍必要。

### 实测发现

下载 `moonbitlang/async@0.22.10` 并检视其 `src/pkg.generated.mbti` 与源码：

- **Semaphore 存在**：`src/semaphore/pkg.generated.mbti` 导出
  - `Semaphore::Semaphore(Int32, initial_value? : Int32) -> Self`
  - `async Semaphore::acquire(Self) -> Unit noraise`
  - `Semaphore::release(Self) -> Unit`
  - `Semaphore::try_acquire(Self) -> Bool`
  - 其 README 明确列出 **Bounded Concurrency**（限制 in-flight job 数）与 **Cancellation Safety** 场景，并强调 `defer release()` 是安全惯例。
- **TaskGroup 能力**：`TaskGroup::spawn` / `spawn_bg` / `spawn_loop`、`with_task_group` 结构化并发。
- **其他同步原语**：`src/mutex.mbt`、`src/cond_var/`、`src/aqueue/`（异步队列，可作生产者-消费者通道）。
- **线程模型（关键）**：`README.md` 第 130 行明确写道
  > "Currently, `moonbitlang/async` features a single-threaded, cooperative multitasking model."
  > "although internally `moonbitlang/async` may use OS threads to perform some IO job,"
  - 即：用户态单线程协作式多任务，内部 IO worker 线程对用户不可见。
- 未发现面向用户的 `thread` / `parallel` 包。

**实测验证**：`p0-spike/t6-fs/t6_walk_test.mbt` 的 `T6b` 用 `Semaphore(2)` + 6 个任务 + `@async.sleep` 验证同时最多 2 个任务在临界区，测试通过（`Total tests: 2, passed: 2`）。

### 结论：**Go（结论修正）**

- T5 原描述"未核实 semaphore/channel"应更新为：**Semaphore 已确认可用，无需自建；无用户态线程，单进程内只有协作式并发**。
- 因此**多进程分片策略仍然必要**（若需要多核加速），但单进程内的并发上限控制可以直接用 `Semaphore`，不必用 Mutex + 计数器手工实现。
- 取消语义仍按 0.22 的新规则处理：`defer` 释放 permit 是必须的模式（Semaphore README 也如此建议）。

### 对 P1 的影响
`orchestrator` 模块设计更新：TaskGroup 负责生命周期、Semaphore 负责并发度、多进程 `--shard i/n` 负责多核。`aqueue` 可作为未来的工作队列扩展点。

---

## 4. T6 — 文件遍历 API

### 判定标准
`@fs` 是否提供 walk/glob；若没有则需自建遍历器。

### 实测发现

`moonbitlang/async@0.22.10` 的 `src/fs/pkg.generated.mbti` 明确导出：

```text
pub async fn walk(StringView,
                  async (String, Array[String]) -> Unit,
                  exclude? : (String) -> Bool,
                  max_concurrency? : Int32,
                  allow_failure? : Bool) -> Unit
pub async fn readdir(StringView, include_hidden?, include_special?, sort?) -> Array[String]
pub async fn opendir(StringView) -> Directory
pub async fn kind(StringView, follow_symlink? : Bool) -> FileKind
pub async fn exists(StringView) -> Bool
pub async fn file_size(StringView) -> Int64
```

`src/fs/dir.mbt:604` 的 `walk` 实现要点（源码确认）：

1. 内部用 `@async.Semaphore(max_concurrency)` 限制并发目录数（默认 1000）。
2. 内部用 TaskGroup + `spawn_bg` 递归处理子目录。
3. 对每个目录，把**子目录路径**加入 `sub_dirs` 继续递归，把**所有条目名（含子目录名）**放进 `files` 数组。
4. 回调签名 `f(path, files)`：`path` 是**目录路径**，`files` 是该目录下所有条目名（包括子目录名），子目录会作为独立的 `path` 再次触发回调。

**实测验证**（`p0-spike/t6-fs/t6_walk_test.mbt` 的 `T6a`）：

```text
$ moon test --target native
Total tests: 2, passed: 2, failed: 0.
```

测试构造 `fixture/{a.mbt, sub/b.mbt, sub/c.txt}`，收集 `(dir, entries)`，得到 4 条记录：
`./fixture/a.mbt`、`./fixture/sub`、`./fixture/sub/b.mbt`、`./fixture/sub/c.txt`
—— 其中 `./fixture/sub` 是作为目录名出现在 `entries` 中，而 `./fixture/sub/b.mbt` 等来自第二次回调。这证实了上述语义。

### 结论：**Go（结论修正）**

- `@fs.walk` 已内置且带 `exclude` 与 `max_concurrency`，**无需自建目录遍历器**。原规划 T6 的"待确认/自建遍历"假设可撤回。
- 需注意语义陷阱：`entries` 含子目录名；扫描器应只按扩展名筛选文件，或在 `exclude` 中按路径规则过滤（`.git`、`node_modules` 等）。
- `kind()` / `file_size()` 可用于"跳过大文件/二进制"和符号链接策略。

### 对 P1 的影响
`source-file` 模块可直接基于 `@fs.walk` 实现，代码量大幅减少；实现时按上述回调语义正确处理子目录条目，避免把目录当源码文件读取。

---

## 5. 四项结论汇总与规划更新

| 项 | 原假设 | 实测结论 | 风险变化 | 必须写进 P1 的设计变更 |
|---|---|---|---|---|
| T2 Windows native | nightly、需 MSVC、需回退 | debug/release 构建运行全部成功，自动定位 MSVC | 高 → 低 | CI 直接用 native release；回退路径降为可选 |
| T3 Query 谓词 | 可能不可用，需全部宿主降级 | `#eq?`/`#match?`/`#any-of?` 完整实现且实测过滤生效 | 中 → 中（转为**版本兼容风险**） | 规则 DSL 直接用谓词；锁 `treesitter@0.1.1+`；准备 grammar 兼容补丁/upstream PR |
| T5 并发 | semaphore/channel 未知，自建 Mutex 计数器 | Semaphore 已存在且适合限流；单线程协作式，无用户态线程 | 中 → 低（但多核仍需多进程） | orchestrator 用 TaskGroup + Semaphore + 多进程 shard |
| T6 文件遍历 | 可能需自建 walk | `@fs.walk` 内置，带 exclude/concurrency；entries 含子目录名 | 中 → 低 | 基于 `@fs.walk` 实现 source-file，注意回调语义 |

### 新增待确认项（由本次实测产生）

| ID | 内容 | 保守处理 |
|---|---|---|
| T11 | grammar 模块兼容补丁能否 upstream；`treesitter@0.1.1` 之后 grammar 是否发布兼容版本 | **已关闭**：不等待上游，用幂等脚本解决；upstream 作为并行改进项 |
| T12 | 各目标 grammar（JavaScript/Python/Java）是否也存在同类编译兼容问题 | **已关闭**：5/5 全中招，已统一修复并实测通过（见第 6 节） |
| T13 | `moonbitlang/async@0.22.10` 与未来 `core/async` 的迁移时间表 | 继续锁版本 + IO 层 trait 隔离 |

---

## 6. T11/T12 — grammar 兼容补丁（补充实测）

### 7.1 T12：问题范围

逐个添加并按 `moonc v0.10.21+06da1ed44` 编译，基线结果：

| grammar 模块 | 版本 | 报错位置 | 结果 |
|---|---|---|---|
| `tree-sitter-javascript` | 0.25.0 | `binding.mbt:29` | ❌ 未打补丁时失败 |
| `tree-sitter-typescript` | 0.23.2 | `binding.mbt:41` | ❌ 未打补丁时失败 |
| `tree-sitter-python` | 0.23.6 | `binding.mbt:29` | ❌ 未打补丁时失败 |
| `tree-sitter-java` | 0.23.5 | `binding.mbt:27` | ❌ 未打补丁时失败 |
| `tree-sitter-json` | 0.24.8 | `binding.mbt:27` | ❌ 未打补丁时失败 |

5/5 完全相同：

```text
Error: [4015] ...binding.mbt:NN
Type @moonbit-community/treesitter/language.CompactError has no method to_string.
(hint: did you mean `Show::to_string`?)
```

**结论**：这是**系统性**缺陷，不是 JSON 个例。根因是上游统一生成脚本 `tools/grammars/update.sh` 为所有 grammar 生成了同一段 `e => abort(e.to_string())`；MoonBit 0.10 起 `impl` 方法不再自动提升为方法调用语法后集体失效。`moon add --upgrade` 对 5 个包均提示已是最新版，官方暂无修复版本。

### 7.2 T11：修复方案选型（含被否决方案）

**实测否决：`moon.work` 本地模块覆盖。** 官方文档支持用 `moon.work` 的 `members` 让同名模块从本地源码解析（忽略 `@version`）。我完整试点了"镜像 grammar 到 `vendor/` + 打补丁 + workspace 覆盖"：

- ✅ 5 个 `to_string` 错误确实消失，证明覆盖机制生效；
- ❌ 但 workspace 模式会编译 `treesitter` 依赖的**所有内部包**，触发新的真实错误：`cli/support` 中 `Fd` 类型不匹配、`regex_syntax/ast.ErrorKind` 与 `OsString` 无 `to_string` 等共 9 处；
- ❌ 不能全局替换 `.to_string()`：`treesitter` 包内有 **321 处**调用，绝大多数是合法的（如 `StringBuilder.to_string()`）。

结论：该方案会把"5 行补丁"放大成"改造整个 treesitter 包"，投入产出比不成立，已删除 `vendor/` 与 `moon.work`。

**实测否决：`postadd` 脚本。** 官方文档确认存在 `options(scripts: {"postadd": "..."})`，但明确标注 *extremely experimental*；且 `moon.mod.json`（早期报告误用的格式）已不被普通工具链接受。不采用。

**采用：幂等原地补丁 + CI 门禁。** 脚本 `scripts/patch_grammars.py`：

- 从项目 `moon.mod` 自动发现 `moonbit-community/tree-sitter-*` 依赖（不硬编码，P1 工程可直接复用）；
- 仅对每个 `binding.mbt` 做精确替换 `e.to_string()` → `Show::to_string(e)`，不改变语义；
- 幂等：重复执行不会重复改写；上游若改用新形式则安全跳过；
- `--check` 模式只读校验，未打补丁时返回非零，可直接做 CI gate。

脚本位于 `p0-spike/t11-t12-grammar/scripts/patch_grammars.py`，支持 `--root <dir>` 指向任意项目。

### 7.3 实测结果

```text
$ cd p0-spike/t11-t12-grammar
$ moon check --target native          # 补丁前
Failed with 0 warnings, 5 errors.      # 全部为 CompactError.to_string

$ python3 scripts/patch_grammars.py
[PATCH] tree-sitter-javascript: fixed=0 applied=1
[PATCH] tree-sitter-typescript: fixed=0 applied=1
[PATCH] tree-sitter-python: fixed=0 applied=1
[PATCH] tree-sitter-java: fixed=0 applied=1
[PATCH] tree-sitter-json: fixed=0 applied=1
OK: 5 grammar(s) compatible with current moonc

$ python3 scripts/patch_grammars.py --check   # CI gate
OK: 5 grammar(s) compatible with current moonc (fixed=5, applied=0)

$ moon check --target native
Finished. moon: ran 6 tasks, now up to date

$ moon test --target native
Total tests: 1, passed: 1, failed: 0.        # 六个 language() 全部成功加载
```

TS grammar 特殊点：导出 `language_tsx()` 与 `language_typescript()` 两个函数（其余 grammar 为 `language()`），规则引擎的 language 注册层需按模块区分。

回归验证：对 `t3-query/` 用同一脚本打补丁后，`T3` 谓词测试仍为 `Total tests: 4, passed: 4, failed: 0`。

### 7.4 对 P1 的影响

- **新增构建步骤**：`moon add` / CI checkout 之后、`moon check|build|test` 之前必须执行补丁脚本；`--check` 加入 CI 前置门禁。
- **版本锁定升级为一等约束**：需在 `moon.mod` 锁定 `treesitter@0.1.1` 与 5 个 grammar 版本；任何 `moon add --upgrade` 后都要重跑补丁与编译验证。
- **风险降级**：T11/T12 从"开工前待确认"变为"已有可控解法"，不再是 P1 阻塞项；剩余风险仅为上游生成脚本变更导致补丁模式失配（脚本会明确报错而非静默通过）。

---

## 7. T4 — 内容指纹与 gitignore 库（补充实测）

### 7.1 核实结论

**`moonbitlang/core` 内置哈希的真相**：`core/builtin/hasher.mbt` 提供 `Hasher` struct，实现的是 **xxHash32**（`GPRIME1..5` 常量可证），方法为 `combine_*` / `finalize() -> Int32`，设计目标是给 `HashMap`/`HashSet` 的 `Hash` trait 用，**不是内容指纹 API**，core 内无任何 SHA-256/FNV 实现。两个必须注意的细节：

- 默认 seed 在 native/JS 为进程随机（JS 从 `crypto.getRandomValues` 取，失败回退 `Math.random`），Wasm 为 0。**用于稳定缓存键必须显式 `Hasher(seed=0)`**。
- 输出仅 32 位，对大代码库指纹去重有碰撞风险，不适合作为唯一内容键。

**registry 候选筛选**（`moon search sha256` / `ignore`）：

| 用途 | 候选 | 结果 |
|---|---|---|
| SHA-256 | `Tigls/mb-hash@0.1.0` | ❌ 包仍是旧 `moon.mod.json` 格式，当前工具链直接拒绝安装 |
| SHA-256 | `gmlewis/sha256@0.18.3` | ✅ 可安装，但 API 仅逐字节 `Digest::write(Byte)` + `check_sum()`，无 one-shot、无 String 输入 |
| SHA-256 | `moonbitstack/mooncrypt@0.5.2` | ✅ 可安装，但拉入 3 个传递依赖（moonbase/moondate/moonseed） |
| SHA-256 | **`mizchi/bit_hash@0.50.0`** | ✅ **选用**：one-shot `sha256_raw(Bytes)`、`Sha256State` 增量、hex 工具；仅依赖 `mizchi/simd@0.6.1`；Apache-2.0 |
| ignore | **`mizchi/bit_ignore@0.50.0`** | ✅ **选用**：零依赖、Apache-2.0，gix-ignore/gix-glob 语义（否定、锚定、目录、嵌套 base、truncate 回溯） |
| ignore | `moonbit-community/ignore@0.0.1` / `sennenki/ignore@0.1.1` | 可用但版本 0.0.x/0.1.x，下载量低，语义覆盖未明确 |

### 7.2 实测结果

工程 `p0-spike/t4-cache-ignore/`，8 个测试在 **native / js / wasm-gc 三个后端全部 8/8 通过**：

```text
=== target native ===  Total tests: 8, passed: 8, failed: 0.
=== target js ===       Total tests: 8, passed: 8, failed: 0.
=== target wasm-gc ===  Total tests: 8, passed: 8, failed: 0.
```

覆盖项：

- `T4a` core `Hasher(seed=0)` 同输入同结果、不同输入不同结果。
- `T4b` `sha256_hex("abc")` == NIST 标准向量 `ba7816bf...15ad`。
- `T4b2` `Sha256State` 增量（"ab"+"c"）== one-shot("abc")。
- `T4b3` 1 字节差异产生不同摘要。
- `T4c` 基本规则：`*.log`、`build/`（目录）。
- `T4c2` 否定规则：`*.log` + `!important.log` 正确反选。
- `T4c3` 锚定差异：`/root-only.txt` 只匹配根，`sub.txt` 匹配任意层级。
- `T4c4` 嵌套 `.gitignore` 的 `base` 参数 + `truncate()` 回溯（遍历时按目录压栈/出栈）。

**踩坑（重要）**：第一版用 `String::to_bytes()` 传给 `sha256_raw`，得到 `13e22856...`，并非标准向量且三个后端行为可疑；该方法已被标记 deprecated。改用 `@encoding/utf8.encode(s)` 后得到正确的 `ba7816bf...`。**所有哈希输入必须显式 UTF-8 编码**。

### 7.3 对 P1 的设计变更

- **缓存键**：`(path, sha256(content via @utf8.encode), rulepack_version, analyzer_version)`，SHA-256 由 `mizchi/bit_hash` 提供；原 FNV-1a 自实现方案作废。
- **指纹去重**：归一化代码片段的 SHA-256 摘要；`core` 的 xxHash32 仅可作为 `HashMap` 内部键（且必须 `seed=0`），不作为持久化指纹。
- **ignore 实现**：`mizchi/bit_ignore` 的 `Matcher` 在遍历时按目录维护规则栈——进入目录 `add_rules(base, content)`，退出时 `truncate(len)`；`is_ignored(rel_path, is_dir)` 直接对接 `@fs.walk` 的回调（`is_dir` 由扩展名/目录集合判定）。原"简化 glob + 正则"方案作废。
- **依赖成本**：新增 2 个直接依赖（共 3 个含 `mizchi/simd`），均为宽松 Apache/MIT 许可，可商用分发。
- **风险**：`mizchi/bit_hash` 与 `bit_ignore` 均为 0.50.0（同作者 `bit-vcs` 项目，2 天前更新，下载量约 3K/2K），仍属较新包；锁版本 +  golden 测试（标准向量与 ignore 语料） mitigate。

---

## 8. P0-1 — 端到端 Finding 输出

工程 `p0-spike/p0-e2e/`，把前面验证过的组件串成完整扫描 CLI：

```text
文件读取(@fs.read_file().text()) → UTF-8(@utf8.encode)
→ Tree-sitter 解析(@js.language() + Parser)
→ Query + #eq? 谓词((call_expression function: (identifier) @callee (#eq? @callee "eval")))
→ Finding(rule_id/severity/line/column/snippet/fingerprint)
→ #derive(@json.ToJson) → Json.stringify() → stdout
```

实测输出（`moon build --target native` 后运行）：

```text
$ main.exe fixture/danger.js
{"file":"fixture/danger.js","finding_count":2,"findings":[
 {"rule_id":"JS001","severity":"HIGH","line":2,"column":1,"snippet":"eval","fingerprint":"cad6a9..."},
 {"rule_id":"JS001","severity":"HIGH","line":4,"column":10,"snippet":"eval","fingerprint":"cad6a9..."}]}

$ main.exe fixture/safe.js
{"file":"fixture/safe.js","finding_count":0,"findings":[]}
```

**结论：Go。** 数据流全通，位置（1-based 行列）与 SHA-256 指纹正确。发现的三个实现细节：

1. **节点类型必须查真实 grammar**：JS 的节点名是 `call_expression`，不是通用的 `call`；写错时 `Query::new` 抛 `Invalid node type "call"`。规则开发必须先查 grammar 的 `node_types.mbt`/`queries/*.scm`。
2. **`#derive(@json.ToJson)` 可直接序列化 struct 与 Array**，无需手写 `Map`；`@json.Json::object()` 才需要 `Map[String, Json]`（不能传 record 字面量）。
3. **async CLI 写法**：`async fn main` + 在 `cmd/main/moon.pkg` 显式导入 `"moonbitlang/async" @async`；根包 `moon.pkg` 的导入**不会传递**到子包，每个 package 必须各自声明依赖。文件读取用 `@fs.read_file(path).text()`（不是 `read_file_to_string`）。

---

## 9. P0-2 — moon cram test

工具链确认：`moon cram test` 存在但标注 **experimental**；底层是 `moon-cram.exe`（`create`/`test`/`update` 三子命令）。测试文件为 Markdown，命令放在 `mooncram` 代码块中：

````markdown
# 用例标题

```mooncram
$ <shell 命令>
<期望 stdout>
[期望退出码]   # 仅在非 0 时写
```
````

**实测结论：Go（带两个必须遵守的条件）。** 工程内 `cram/finding.md` 3/3 通过：

```text
$ moon cram test cram/
Result: 1 document(s) with 3 testcase(s): 3 succeeded, 0 failed and 0 skipped
```

三个用例：检出 `eval` 输出 1 条 Finding、干净样本输出 0 条、缺参数输出 usage 并退出 127（MoonBit `abort` 的退出码就是 127，不是常见的 1）。故意改错期望值后测试报 1 failed，进程退出码 **50**——失败可被 CI 正确捕获。

**两个必须写进 CI 的条件**：

1. **必须显式传测试目录/文件**：`moon cram test` 无参数时报告 `0 document(s) with 0 testcase(s)` 且退出码 0，等于静默跳过全部端到端测试。CI 必须写 `moon cram test tests/cram/`。
2. **每个 `mooncram` 代码块是独立的 shell 表达式**，在各自的临时工作目录中执行，块之间不共享文件或变量。因此 fixture 要在同一条表达式里自建，例如 `printf '...' > sample.js && main.exe sample.js`。构建出的可执行文件由 `moon cram test` 自动加入 PATH，可直接写裸命令 `main.exe`（`moon-cram create` 单独调用时没有这个 PATH，会记录错误的 `[127]`，不要直接用它生成的期望值）。

---

## 10. P0 收尾状态

| 项 | 状态 |
|---|---|
| T1（1.0 发布时间） | 仅作持续观察项：`v0.10.21` 于 2026-11-16 发布，1.0 未到；不影响 P1 开发 |
| T2 / T3 / T4 / T5 / T6 / T11 / T12 | 全部关闭，均有实测结论与可复跑工程 |
| P0-1 端到端 Finding | ✅ 已验证，工程 `p0-spike/p0-e2e/` |
| P0-2 `moon cram test` | ✅ 已验证，3/3 通过，两个 CI 条件已记录 |

**P0 全部完成，P1（MVP）开发无前置阻塞。** 进入 P1 时的两个构建约定：依赖拉取后执行 `scripts/patch_grammars.py`（`--check` 作 CI 门禁）；CI 显式调用 `moon cram test <目录>`。
