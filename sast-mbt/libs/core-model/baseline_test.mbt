///|
fn fp_finding(fp : String) -> @core-model.Finding {
  {
    rule_id: "CFG001",
    severity: @core-model.High,
    confidence: @core-model.High,
    cwe: [],
    owasp: [],
    primary: { path: "a.json", line: 1, column: 1, byte_offset: 0, },
    related: [],
    message: "plaintext password",
    snippet: fp,
    fingerprint: fp,
    baseline_state: @core-model.NotCompared,
  }
}

///|
fn fp_result(findings : Array[@core-model.Finding]) -> @core-model.ScanResult {
  {
    findings,
    warnings: [],
    skipped_files: [],
    stats: {
      files_scanned: 1,
      files_skipped: 0,
      bytes_scanned: 4,
      raw_hits: findings.length().to_int(),
      duration_ms: 0,
    },
  }
}

///|
test "baseline: parse fingerprints from a JSON report" {
  let text = "{\"findings\":[{\"fingerprint\":\"a\"},{\"fingerprint\":\"b\"},{\"message\":\"no fp\"}]}"
  let known = @core-model.parse_baseline_fingerprints(text).unwrap()
  assert_eq(known.get("a"), Some(true))
  assert_eq(known.get("b"), Some(true))
  assert_eq(known.get("message"), None)
  assert_eq(@core-model.parse_baseline_fingerprints("not json"), None)
  assert_eq(@core-model.parse_baseline_fingerprints("{\"findings\":42}"), None)
}

///|
test "baseline: unchanged findings are marked and pruned" {
  let known : Map[String, Bool] = Map([("old", true)])
  let marked = @core-model.mark_baseline(
    fp_result([fp_finding("old"), fp_finding("new")]),
    known,
  )
  assert_eq(marked.findings[0].baseline_state, @core-model.Unchanged)
  assert_eq(marked.findings[1].baseline_state, @core-model.New)
  let fresh = @core-model.keep_new(marked)
  assert_eq(fresh.findings.length(), 1)
  assert_eq(fresh.findings[0].fingerprint, "new")
  assert_eq(fresh.findings[0].baseline_state, @core-model.New)
}

///|
test "baseline: names are the SARIF vocabulary" {
  assert_eq(
    @core-model.baseline_state_name(@core-model.NotCompared),
    "not-compared",
  )
  assert_eq(@core-model.baseline_state_name(@core-model.New), "new")
  assert_eq(@core-model.baseline_state_name(@core-model.Unchanged), "unchanged")
}
