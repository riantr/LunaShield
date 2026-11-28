# MCIL go/no-go spike（P2）

**结论：技术判据 GO（2026-11-28 复测）。** 构建、`sample.c` 解析、CFG 导出三项全部通过；是否正式纳入 LunaShield 的 C/C++ 深度分析路径，仍取决于是否接受维护本地 fork（清单/语法迁移）的长期成本。C/C++ 目前仍归属「未来可选」，并按 R10 借鉴其 IR/CFG/dataflow 设计。证据见下节。

## 实测环境与步骤

- MoonBit（原实测）：`moon 0.1.20261117`，`moonc 0.10.21+06da1ed44`，native 目标；最新版复测见下节。
- 依赖声明：`moon.mod` 中 `Lampese/MCIL@0.1.1`。
- 样例：`sample.c`（C99，`argv[1]` → `snprintf` → `system`）。

```bash
cd p0-spike/mcil
moon check --target native
```

实际输出（关键行）：

```text
Using cached moonbitlang/async@0.15.0
Downloading Lampese/MCIL@0.1.1
Error: Failed to calculate build plan
Caused by:
    0: Failed to resolve the module dependency graph
    1: When installing packages
    2: `moon.mod.json` at '.../p0-spike/mcil/.mooncakes/.source-yKm3CG' is no longer supported.
       Run `moon fmt` to migrate to `moon.mod`.
```

继续尝试迁移：从 `~/.moon/registry/cache/Lampese/MCIL/0.1.1.zip` 解包后运行 `moon fmt`，
顶层元数据可迁移（生成 `moon.mod` / `moon.pkg`），但再次 `moon check` 仍因同一错误失败：
MCIL 固定的 `moonbitlang/async@0.15.0` 也是旧 `moon.mod.json` 格式，需要递归 fork + 迁移。
主工程使用 `moonbitlang/async@0.22.9`，版本漂移还可能带来 API 不兼容。

## 2026-11-28 复测：最新版 moonc

在已升级到当前最新工具链的环境下重新执行同一判据：

- MoonBit：`moon 0.1.20261126 (ccd306a)`，`moonc v1.0.0-rc1+3c0520448`，native 目标。
- `moon update` 刷新 registry 后，`cd p0-spike/mcil && moon check --target native` 仍报同一错误：
  `moon.mod.json ... is no longer supported. Run moon fmt to migrate to moon.mod.`
- `moon view Lampese/MCIL --versions` 仅有 `0.1.0` / `0.1.1`，最新仍是 `0.1.1`（发布于 2026-01-09）；
  上游 `github.com/Lampese/MCIL` 默认分支 `main` 最后推送为 2026-01-12，仓库仍使用 `moon.mod.json` / `moon.pkg.json`，没有可供升级的新版本。

进一步做了「本地迁移」实验（临时目录，不入库）：

1. 解压 `Lampese/MCIL@0.1.1` 后运行 `moon fmt`，清单可迁到 `moon.mod` / `moon.pkg`；
2. MCIL 固定的 `moonbitlang/async@0.15.0` 换成已使用新格式的 `0.22.10`，并用 workspace 同时覆盖 MCIL / async 两个本地模块；
3. 编译驱动（仅引用 `src/cil`、`src/frontc`、`src/ext`）仍在 `src/cil` 报 **24 个错误**，分布在 8 个文件：
   - 4 个 `[3002]`：旧式 `for ... {} else {}` 语法，最新 moonc 要求 `nobreak`；
   - 18 个 `[4037]`：`@hashset` 等 core 包不再隐式导入，需要显式声明；
   - 2 个 `[4015]` / `[4018]`：`to_string` / `ToStringView` 相关 API 漂移。

按上述清单做了最小修复：`src/cil/moon.pkg` 加 `"moonbitlang/core/hashset"` 后，18 个 `[4037]` 与 2 个连带类型错误消失；`dataflow.mbt:98`、`printer.mbt:6/108/150` 的 4 处 `for...else` 改为显式循环后，**原 24 个错误全部清零**。

但编译器随后进入 `src/ext` / `src/frontc`，又报 **69 个错误**：19 个同类 `@hashset` 未导入（`callgraph` / `canonicalize` / `rmtmps` / `usedef`），7 个旧式 `suberror X String` 声明，39 个由其导致的 `raise X(...)` 常量构造器错误，4 个类型推断连带错误。

继续修复类型连带错误：`src/ext/moon.pkg` 补 `hashset` import，清掉 19 个 `[4037]` 及 `callgraph.mbt:302/325/332` 三个类型错误；`src/frontc/parser.mbt:252` 把 `tok.to_string()` 改为 `Show::to_string(tok)`，清掉最后一个。错误数从 69 降到 **46**。

继续清理最后 46 个：`inliner.mbt:2`、`cabs2cil.mbt:84`、`parser.mbt:9`、`preprocess.mbt:41` 四处 `suberror X String` 改为带位置参数构造器的新写法；`runall.mbt:32/97/149` 三处 `for...else` 改为普通循环；驱动 `spike/main.mbt` 同步改用 `catch` 处理 `raise` 错误，并调用 `compute_file_cfg`。重编译 `moon run spike --target native`：**0 错误、EXIT=0**，输出 `MCIL parse + cabs2cil OK` 与 `fun=main stmts=1 sinks=1`。原始 24 个错误 + 后续 69 个错误全部清零。

复跑 `moon run spike --target native`：**0 错误、EXIT=0**，输出 `MCIL parse + cabs2cil OK`，并打印两个函数的 CFG DOT：

- `run_query`：3 stmts / 1 sink，CFG `0 -> 1 -> 2`
- `main`：4 stmts / 1 sink，CFG `5(if) -> 4(block) -> 3(instr) -> 6(return)`，另有 `5 -> 6` 旁路

原先 NO-GO 的技术理由（旧清单与旧语法不兼容最新 moonc）在本地 fork + 迁移后已消除，三项判据全部通过。

## 判据与决策

原规划要求：能构建、能解析 C99 样例、能导出 CFG，三条全部通过才 GO。

| 判据 | 结果 | 证据 |
|---|---|---|
| 直接构建 | 通过（本地 fork + 迁移） | 清单迁到 `moon.mod`、async 升到 0.22.10、语法适配后 `moon run` 0 错误 |
| 解析 C99 样例 | 通过 | `sample.c` 解析出 `run_query` 与 `main` 两个函数并生成 CIL |
| 导出 CFG | 通过 | `print_cfg_dot` 输出两个函数的 DOT 图，含分支旁路 |

因此技术判据 **GO**：在最新版 moonc 下，MCIL 通过本地 fork + 清单/语法迁移后，构建、C99 样例解析与 CFG 导出三项全部通过。
是否正式纳入仍取决于是否接受维护私有 fork 的长期成本。

## 保留价值与替代路线

- 设计借鉴：MCIL 的 `cabs2cil` → CIL IR → CFG / dominator / liveness / use-def 分层，
  是后续自研过程内分析的参考；其源码已在 spike 中解压检查过（不入库）。
- 已落地的替代：`sast-mbt/libs/dataflow` 提供显式 CFG + worklist 不动点分析
  （`build_cfg` / `solve` / `reachable`），以变量集合为格，支持分支旁路和循环收敛。
- 若正式纳入 C 线，需把本次本地 fork 的清单/语法迁移补丁固化为可维护补丁集，并跟进 MCIL 上游对新清单格式与 moonc 的适配；
  `sample.c` 可继续作为回归样例。
