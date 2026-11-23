///|
fn sample_result() -> @core.ScanResult {
  let finding : @core.Finding = {
    rule_id: "JS001",
    severity: @core.High,
    confidence: @core.High,
    cwe: [95],
    owasp: ["A03:2021"],
    primary: { path: "a.js", line: 2, column: 1, byte_offset: 13, },
    related: [],
    message: "Dynamic code execution via eval()",
    snippet: "eval",
    fingerprint: "cad6a9d402bd4d6c926a60f7d06d046c4fdf4b613dab5be32c2189e45cd3da31",
  }
  let warning : @core.ParseWarning = {
    path: "b.js",
    line: 3,
    column: 5,
    message: "syntax error",
  }
  {
    findings: [finding],
    warnings: [warning],
    skipped_files: ["c.bin (binary)"],
    stats: {
      files_scanned: 2,
      files_skipped: 1,
      bytes_scanned: 42,
      raw_hits: 3,
      duration_ms: 0,
    },
  }
}

///|
test "console: summary and finding lines are stable" {
  let text = @report.render_console(sample_result())
  assert_true(text.has_prefix("LunaShield 0.1.0\n"))
  assert_true(text.contains("files: 2 scanned, 1 skipped, 3 raw hits\n"))
  assert_true(
    text.contains("findings: 1 (critical 0, high 1, medium 0, low 0, info 0)\n"),
  )
  assert_true(
    text.contains("a.js:2:1 JS001 [high] Dynamic code execution via eval()\n"),
  )
  assert_true(text.contains("warnings: 1\n"))
  assert_true(text.has_suffix("b.js:3:5 syntax error"))
}

///|
test "json: fixed key order, lowercase severity, no timestamps" {
  let text = @report.render_json(sample_result())
  assert_true(text.has_prefix("{\"version\":\"0.1.0\",\"stats\":{"))
  assert_true(text.contains("\"severity\":\"high\""))
  assert_true(text.contains("\"confidence\":\"high\""))
  assert_true(
    text.contains(
      "\"fingerprint\":\"cad6a9d402bd4d6c926a60f7d06d046c4fdf4b613dab5be32c2189e45cd3da31\"",
    ),
  )
  assert_true(text.contains("\"skipped_files\":[\"c.bin (binary)\"]"))
  assert_true(!text.contains("time"))
}

///|
test "json: renders identically for equal inputs" {
  assert_eq(
    @report.render_json(sample_result()),
    @report.render_json(sample_result()),
  )
}

///|
test "junit: one testcase per finding with escaped attributes" {
  let text = @report.render_junit(sample_result())
  assert_true(text.has_prefix("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"))
  assert_true(
    text.contains("<testsuite name=\"sast\" tests=\"1\" failures=\"1\""),
  )
  assert_true(text.contains("<testcase classname=\"JS001\" name=\"a.js:2:1\">"))
  assert_true(
    text.contains("<failure message=\"Dynamic code execution via eval()\">"),
  )
  assert_true(text.contains("        eval"))
}

///|
test "junit: xml special characters are escaped" {
  let evil : @core.Finding = {
    rule_id: "JS<00>1",
    severity: @core.Low,
    confidence: @core.High,
    cwe: [],
    owasp: [],
    primary: { path: "a&b.js", line: 1, column: 1, byte_offset: 0, },
    related: [],
    message: "x < y && z > w \"q\" 'r'",
    snippet: "<script>",
    fingerprint: "f",
  }
  let result : @core.ScanResult = {
    findings: [evil],
    warnings: [],
    skipped_files: [],
    stats: {
      files_scanned: 1,
      files_skipped: 0,
      bytes_scanned: 1,
      raw_hits: 1,
      duration_ms: 0,
    },
  }
  let text = @report.render_junit(result)
  assert_true(text.contains("classname=\"JS&lt;00&gt;1\""))
  assert_true(text.contains("name=\"a&amp;b.js:1:1\""))
  assert_true(
    text.contains("x &lt; y &amp;&amp; z &gt; w &quot;q&quot; &apos;r&apos;"),
  )
  assert_true(text.contains("&lt;script&gt;"))
}

///|
test "render: medium confidence is spelled out in the JSON DTO" {
  let f : @core.Finding = {
    rule_id: "JS001",
    severity: @core.High,
    confidence: @core.Medium,
    cwe: [95],
    owasp: ["A03:2021"],
    primary: { path: "a.js", line: 1, column: 1, byte_offset: 0, },
    related: [],
    message: "m",
    snippet: "eval",
    fingerprint: "f",
  }
  let result : @core.ScanResult = {
    findings: [f],
    warnings: [],
    skipped_files: [],
    stats: {
      files_scanned: 1,
      files_skipped: 0,
      bytes_scanned: 1,
      raw_hits: 1,
      duration_ms: 0,
    },
  }
  assert_true(@report.render_json(result).contains("\"confidence\":\"medium\""))
}
