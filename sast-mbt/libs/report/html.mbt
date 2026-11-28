// P3: HTML reporter. Deterministic, dependency-free, and escaped: finding
// text is attacker-controlled source code and must never become markup.

///|
fn escape_html(s : String) -> String {
  let parts : Array[String] = []
  for c in s {
    match c {
      '&' => parts.push("&amp;")
      '<' => parts.push("&lt;")
      '>' => parts.push("&gt;")
      '"' => parts.push("&quot;")
      '\'' => parts.push("&#39;")
      _ => parts.push("\{c}")
    }
  }
  parts.join("")
}

///|
fn row(f : @core.Finding) -> String {
  "<tr><td>" +
  escape_html(f.rule_id) +
  "</td><td>" +
  escape_html(@core.severity_name(f.severity)) +
  "</td><td>" +
  escape_html(f.primary.path) +
  "</td><td>" +
  f.primary.line.to_string() +
  "</td><td>" +
  escape_html(f.message) +
  "</td></tr>"
}

///|
/// Self-contained HTML page. Rows follow the canonical finding order from the
/// orchestrator; no timestamps or absolute paths are emitted.
pub fn render_html(result : @core.ScanResult) -> String {
  let rows : Array[String] = []
  for f in result.findings {
    rows.push(row(f))
  }
  "<!doctype html>\n" +
  "<html lang=\"en\">\n" +
  "<head><meta charset=\"utf-8\"><title>LunaShield findings</title></head>\n" +
  "<body>\n" +
  "<h1>LunaShield findings</h1>\n" +
  "<p>scanned: " +
  result.stats.files_scanned.to_string() +
  ", findings: " +
  result.findings.length().to_string() +
  "</p>\n" +
  "<table>\n" +
  "<thead><tr><th>Rule</th><th>Severity</th><th>Path</th><th>Line</th><th>Message</th></tr></thead>\n" +
  "<tbody>\n" +
  rows.join("\n") +
  (if rows.length() > 0 { "\n" } else { "" }) +
  "</tbody>\n" +
  "</table>\n" +
  "</body>\n" +
  "</html>"
}

///|
pub impl Reporter for HtmlReporter with fn name(_self) {
  "html"
}

///|
pub impl Reporter for HtmlReporter with fn render(_self, result) {
  render_html(result)
}

///|
pub impl Reporter for HtmlReporter with fn file_name(_self) {
  Some("findings.html")
}
