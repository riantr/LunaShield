///|
fn hostile_result() -> @core.ScanResult {
  let finding : @core.Finding = {
    rule_id: "JS<001>",
    severity: @core.High,
    confidence: @core.High,
    cwe: [],
    owasp: [],
    primary: { path: "a&b.js", line: 3, column: 1, byte_offset: 0, },
    related: [],
    message: "x <script>alert(1)</script> & \"q\"",
    snippet: "<script>",
    fingerprint: "f",
    baseline_state: @core.NotCompared,
  }
  {
    findings: [finding],
    warnings: [],
    skipped_files: [],
    stats: {
      files_scanned: 2,
      files_skipped: 0,
      bytes_scanned: 42,
      raw_hits: 1,
      duration_ms: 0,
    },
  }
}

///|
test "html: finding text is escaped and output is deterministic" {
  let text = @report.render_html(hostile_result())
  assert_true(text.has_prefix("<!doctype html>\n"))
  assert_true(text.contains("&lt;script&gt;"))
  assert_true(text.contains("&amp;"))
  assert_true(text.contains("&quot;q&quot;"))
  assert_true(!text.contains("<script>"))
  assert_true(text.contains("a&amp;b.js"))
  assert_eq(text, @report.render_html(hostile_result()))
  assert_eq(text.has_suffix("</html>"), true)
}

///|
test "html: reporter is registered with the canonical file name" {
  match @report.reporter_for("html") {
    None => abort("html reporter not registered")
    Some(rep) => {
      assert_eq(rep.name(), "html")
      assert_eq(rep.file_name(), Some("findings.html"))
      assert_true(rep.render(hostile_result()).contains("LunaShield findings"))
    }
  }
  assert_true(@report.supported_formats().contains("html"))
}

///|
test "html: empty result still emits a valid table" {
  let empty : @core.ScanResult = {
    findings: [],
    warnings: [],
    skipped_files: [],
    stats: {
      files_scanned: 0,
      files_skipped: 0,
      bytes_scanned: 0,
      raw_hits: 0,
      duration_ms: 0,
    },
  }
  let text = @report.render_html(empty)
  assert_true(text.contains("<tbody>\n</tbody>"))
  assert_true(text.contains("findings: 0"))
}
