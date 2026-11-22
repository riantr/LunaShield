// SARIF 2.1.0 minimal profile (P2-S1).
//
// Hand-rolled JSON on purpose: SARIF needs key names like "$schema" that cannot
// be struct fields, and we must keep key order deterministic (no Map iteration).

///|
pub const SARIF_VERSION : String = "2.1.0"

///|
pub const SARIF_SCHEMA : String = "https://json.schemastore.org/sarif-2.1.0.json"

///|
pub const PROJECT_URL : String = "https://gitee.com/ren-yongxiang/LunaShield"

///|
fn json_escape(s : String) -> String {
  let parts : Array[String] = []
  for c in s {
    if c == '"' {
      parts.push("\\\"")
    } else if c == '\\' {
      parts.push("\\\\")
    } else if c == '\n' {
      parts.push("\\n")
    } else if c == '\r' {
      parts.push("\\r")
    } else if c == '\t' {
      parts.push("\\t")
    } else {
      parts.push("\{c}")
    }
  }
  parts.join("")
}

///|
fn quoted(s : String) -> String {
  "\"" + json_escape(s) + "\""
}

///|
/// SARIF result level. Critical and High are errors (they fail the gate by
/// default), Medium is a warning, Low/Info are notes.
pub fn sarif_level(sev : @core.Severity) -> String {
  match sev {
    @core.Critical => "error"
    @core.High => "error"
    @core.Medium => "warning"
    @core.Low => "note"
    @core.Info => "note"
  }
}

///|
/// Driver rules array: one entry per distinct rule id, sorted by id, with the
/// rule message as its short description.
fn sarif_rules(findings : Array[@core.Finding]) -> String {
  let entries : Array[(String, String)] = []
  for f in findings {
    let mut known = false
    for e in entries {
      if e.0 == f.rule_id {
        known = true
      }
    }
    if !known {
      entries.push((f.rule_id, f.message))
    }
  }
  entries
  .mut_view()
  .sort_by(fn(a, b) { a.0[:].lexical_compare(b.0[:]).to_int() })
  let parts : Array[String] = []
  for e in entries {
    parts.push(
      "{\"id\":\{quoted(e.0)},\"shortDescription\":{\"text\":\{quoted(e.1)}}}",
    )
  }
  "[" + parts.join(",") + "]"
}

///|
fn sarif_result(f : @core.Finding) -> String {
  "{" +
  "\"ruleId\":" +
  quoted(f.rule_id) +
  "," +
  "\"level\":" +
  quoted(sarif_level(f.severity)) +
  "," +
  "\"message\":{\"text\":" +
  quoted(f.message) +
  "}," +
  "\"locations\":[{\"physicalLocation\":{" +
  "\"artifactLocation\":{\"uri\":" +
  quoted(f.primary.path) +
  "}," +
  "\"region\":{\"startLine\":" +
  f.primary.line.to_string() +
  ",\"startColumn\":" +
  f.primary.column.to_string() +
  ",\"byteOffset\":" +
  f.primary.byte_offset.to_string() +
  "}" +
  "}}]," +
  "\"partialFingerprints\":{\"primaryLocationLineHash\":" +
  quoted(f.fingerprint) +
  "}" +
  "}"
}

///|
/// Render a SARIF 2.1.0 log for external consumers (code scanning dashboards,
/// IDE plugins). Compact JSON, deterministic key order, one result per finding.
pub fn render_sarif(result : @core.ScanResult) -> String {
  let results : Array[String] = []
  for f in result.findings {
    results.push(sarif_result(f))
  }
  let driver = "{\"name\":" +
    quoted(PRODUCT_NAME) +
    ",\"version\":" +
    quoted(ANALYZER_VERSION) +
    ",\"informationUri\":" +
    quoted(PROJECT_URL) +
    ",\"rules\":" +
    sarif_rules(result.findings) +
    "}"
  "{" +
  "\"version\":" +
  quoted(SARIF_VERSION) +
  "," +
  "\"$schema\":" +
  quoted(SARIF_SCHEMA) +
  "," +
  "\"runs\":[{\"tool\":{\"driver\":" +
  driver +
  "}," +
  "\"results\":[" +
  results.join(",") +
  "]}]" +
  "}"
}
