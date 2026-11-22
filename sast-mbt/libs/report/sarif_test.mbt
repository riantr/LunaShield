///|
fn sarif_finding(
  sev : @core.Severity,
  message : String,
  snippet : String,
) -> @core.Finding {
  {
    rule_id: "JS001",
    severity: sev,
    confidence: @core.High,
    cwe: [95],
    owasp: ["A03:2021"],
    primary: { path: "src/a.js", line: 2, column: 3, byte_offset: 17, },
    related: [],
    message,
    snippet,
    fingerprint: "cad6a9d402bd4d6c926a60f7d06d046c4fdf4b613dab5be32c2189e45cd3da31",
  }
}

///|
fn sarif_result_of(findings : Array[@core.Finding]) -> @core.ScanResult {
  {
    findings,
    warnings: [],
    skipped_files: [],
    stats: {
      files_scanned: 1,
      files_skipped: 0,
      bytes_scanned: 10,
      raw_hits: findings.length().to_int(),
      duration_ms: 0,
    },
  }
}

///|
test "sarif: log header and driver are stable" {
  let text = @report.render_sarif(
    sarif_result_of([
      sarif_finding(@core.High, "Dynamic code execution via eval()", "eval"),
    ]),
  )
  assert_true(
    text.has_prefix(
      "{\"version\":\"2.1.0\",\"$schema\":\"https://json.schemastore.org/sarif-2.1.0.json\",\"runs\":[{\"tool\":{\"driver\":{\"name\":\"LunaShield\"",
    ),
  )
  assert_true(
    text.contains(
      "\"rules\":[{\"id\":\"JS001\",\"shortDescription\":{\"text\":\"Dynamic code execution via eval()\"}}]",
    ),
  )
  assert_true(
    text.has_suffix(
      "\"results\":[{\"ruleId\":\"JS001\",\"level\":\"error\",\"message\":{\"text\":\"Dynamic code execution via eval()\"},\"locations\":[{\"physicalLocation\":{\"artifactLocation\":{\"uri\":\"src/a.js\"},\"region\":{\"startLine\":2,\"startColumn\":3,\"byteOffset\":17}}}],\"partialFingerprints\":{\"primaryLocationLineHash\":\"cad6a9d402bd4d6c926a60f7d06d046c4fdf4b613dab5be32c2189e45cd3da31\"}}]}]}",
    ),
  )
}

///|
test "sarif: severity maps to level error/warning/note" {
  assert_eq(@report.sarif_level(@core.Critical), "error")
  assert_eq(@report.sarif_level(@core.High), "error")
  assert_eq(@report.sarif_level(@core.Medium), "warning")
  assert_eq(@report.sarif_level(@core.Low), "note")
  assert_eq(@report.sarif_level(@core.Info), "note")
}

///|
test "sarif: quotes, backslashes and newlines are escaped" {
  let evil = sarif_finding(@core.Medium, "say \"hi\"\\path\nnext", "x")
  let text = @report.render_sarif(sarif_result_of([evil]))
  assert_true(text.contains("\"text\":\"say \\\"hi\\\"\\\\path\\nnext\""))
  assert_true(text.contains("\"level\":\"warning\""))
}

///|
test "sarif: two identical inputs render byte-identically" {
  let findings = [sarif_finding(@core.High, "m", "eval")]
  assert_eq(
    @report.render_sarif(sarif_result_of(findings)),
    @report.render_sarif(sarif_result_of(findings)),
  )
}

///|
test "sarif: empty result still emits a valid empty results array" {
  let text = @report.render_sarif(sarif_result_of([]))
  assert_true(text.contains("\"rules\":[]"))
  assert_true(text.has_suffix("\"results\":[]}]}"))
}
