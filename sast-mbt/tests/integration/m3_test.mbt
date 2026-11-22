// M3 regression: the full parse -> query -> score pipeline must reproduce the
// P0 end-to-end baseline byte for byte (fingerprints included).

///|
async test "P0 baseline: danger.js yields two raw hits collapsing to one finding" {
  let result = @integration-tests.scan_file("fixtures/danger.js")
  assert_eq(result.stats.raw_hits, 2)
  assert_eq(result.findings.length(), 1)
  let f = result.findings[0]
  assert_eq(f.rule_id, "JS001")
  assert_eq(f.severity, @core.High)
  assert_eq(f.confidence, @core.High)
  assert_eq(f.primary.path, "fixtures/danger.js")
  assert_eq(f.primary.line, 2)
  assert_eq(f.primary.column, 1)
  assert_eq(f.snippet, "eval")
  assert_eq(f.message, "Dynamic code execution via eval()")
  // Byte-identical with the P0 e2e JSON (`cad6a9...`).
  assert_eq(f.fingerprint, @integration-tests.P0_FINGERPRINT)
}

///|
async test "P0 baseline: safe.js yields nothing" {
  let result = @integration-tests.scan_file("fixtures/safe.js")
  assert_eq(result.stats.raw_hits, 0)
  assert_eq(result.findings.length(), 0)
}

///|
async test "rule semantics: string literal argument is not reported" {
  let result = @integration-tests.scan_file("fixtures/literal.js")
  assert_eq(result.stats.raw_hits, 0)
  assert_eq(result.findings.length(), 0)
}

///|
async test "rule semantics: sast-ignore suppresses only the marked line" {
  let result = @integration-tests.scan_file("fixtures/suppressed.js")
  // Three eval calls in total, one of them suppressed.
  assert_eq(result.stats.raw_hits, 3)
  assert_eq(result.findings.length(), 1)
  assert_eq(result.findings[0].primary.line, 3)
}

///|
async test "determinism: two runs render identical output" {
  let first = @integration-tests.render(
    @integration-tests.scan_file("fixtures/suppressed.js"),
  )
  let second = @integration-tests.render(
    @integration-tests.scan_file("fixtures/suppressed.js"),
  )
  assert_eq(first, second)
  assert_eq(first.length() > 0, true)
}
