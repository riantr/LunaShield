# Official rule pack

本目录既是扫描器默认读取的规则包目录，也是一个可发布的 MoonBit 数据模块
（`lunashield/official-rules`）。

- `moon.mod` 的版本即规则包快照版本；发布时 bump 版本并重新生成 `manifest.json`。
- `rules.json` / `taint.json` 是唯一数据源，`manifest.json` 保存两者的 SHA-256；
  `gen_rulepack.py` 负责同步三者，不要手工编辑摘要。
- `pack.mbt` 暴露版本与规则数，供依赖该模块的消费方做编译期断言。

发布与消费（需要 mooncakes.io 账号）：

```bash
cd rulepacks/official
moon publish
# 消费方
moon add lunashield/official-rules@1.0.0
```

发布前后都应运行 `python3 scripts/gen_rulepack.py --check` 与
`bash scripts/check_rules_validate.sh`，确保摘要与规则内容一致。
