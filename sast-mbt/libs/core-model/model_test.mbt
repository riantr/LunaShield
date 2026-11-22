///|
test "severity rank ordering" {
  assert_true(
    @core-model.severity_rank(@core-model.Critical) >
    @core-model.severity_rank(@core-model.High),
  )
  assert_true(
    @core-model.severity_rank(@core-model.High) >
    @core-model.severity_rank(@core-model.Medium),
  )
  assert_true(
    @core-model.severity_rank(@core-model.Medium) >
    @core-model.severity_rank(@core-model.Low),
  )
  assert_true(
    @core-model.severity_rank(@core-model.Low) >
    @core-model.severity_rank(@core-model.Info),
  )
}

///|
test "severity string roundtrip" {
  let names = ["critical", "high", "medium", "low", "info"]
  for name in names {
    guard @core-model.severity_from_string(name) is Some(s) else {
      abort("severity_from_string failed for \{name}")
    }
    assert_eq(@core-model.severity_name(s), name)
  }
  assert_eq(@core-model.severity_from_string("bogus"), None)
}

///|
test "SourceLoc and Finding fields" {
  let loc = @core-model.SourceLoc::{
    path: "a.js",
    line: 1,
    column: 2,
    byte_offset: 3,
  }
  assert_eq(loc.line, 1)
  assert_eq(loc.column, 2)
  let empty : Array[@core-model.SourceLoc] = []
  let finding = @core-model.Finding::{
    rule_id: "JS001",
    severity: @core-model.High,
    confidence: @core-model.High,
    cwe: [95],
    owasp: ["A03:2021"],
    primary: loc,
    related: empty,
    message: "eval",
    snippet: "eval(x)",
    fingerprint: "abc",
  }
  assert_eq(finding.rule_id, "JS001")
  assert_eq(finding.severity, @core-model.High)
}
