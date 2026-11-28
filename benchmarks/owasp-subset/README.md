# OWASP-style FP subset

本地可控的注入类误报基准（不是 OWASP Benchmark 官方数据集的完整镜像）：

- `safe/`：10 个 JS 样例，AST 规则会命中，但变量来自配置/缓存或经过白名单清洗，
  不应报为漏洞（`eval(CONFIG.script)`、`eval(escapeHtml(req.query.x))` 等）。
- `vulnerable/`：4 个 JS 样例，用户可控输入直接到达 `eval`，必须继续检出。

判定口径：P1 = 纯 AST 规则（`--taint off`），P2 = AST + 污点 strict
（`--taint strict`）。FP 率 = 在 `safe/` 上产生 finding 的文件数 / 安全文件数。
规划要求 P2 相对 P1 严格下降且不超过 0.10。

复跑（需要先构建 native 扫描器）：

```bash
cd sast-mbt
moon build --target native apps/scan
python3 ../benchmarks/owasp-subset/check_fp.py
```

结果写入 `report.json`（无时间戳，可入库）。`p2_loop.py --gate benchmark`
读取该文件并校验阈值。
