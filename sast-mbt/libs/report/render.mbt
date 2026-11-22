// Three MVP renderers (console / json / junit) over one DTO layer.
//
// Determinism contract: no timestamps, no absolute paths (the orchestrator already
// stores root-relative POSIX paths), and JSON is produced from fixed-order structs
// instead of a Map so key order never depends on hashing.

///|
pub const PRODUCT_NAME : String = "LunaShield"

///|
pub const ANALYZER_VERSION : String = "0.1.0"

///|
#derive(@json.ToJson)
pub(all) struct LocDto {
  path : String
  line : Int32
  column : Int32
  byte_offset : Int32
}

///|
#derive(@json.ToJson)
pub(all) struct FindingDto {
  rule_id : String
  severity : String
  confidence : String
  cwe : Array[Int32]
  owasp : Array[String]
  primary : LocDto
  message : String
  snippet : String
  fingerprint : String
}

///|
#derive(@json.ToJson)
pub(all) struct WarningDto {
  path : String
  line : Int32
  column : Int32
  message : String
}

///|
#derive(@json.ToJson)
pub(all) struct StatsDto {
  files_scanned : Int32
  files_skipped : Int32
  bytes_scanned : Int32
  raw_hits : Int32
}

///|
#derive(@json.ToJson)
pub(all) struct ReportDto {
  version : String
  stats : StatsDto
  warnings : Array[WarningDto]
  skipped_files : Array[String]
  findings : Array[FindingDto]
}

///|
fn loc_dto(loc : @core.SourceLoc) -> LocDto {
  {
    path: loc.path,
    line: loc.line,
    column: loc.column,
    byte_offset: loc.byte_offset,
  }
}

///|
fn finding_dto(f : @core.Finding) -> FindingDto {
  {
    rule_id: f.rule_id,
    severity: @core.severity_name(f.severity),
    confidence: match f.confidence {
      @core.High => "high"
      @core.Medium => "medium"
      @core.Low => "low"
    },
    cwe: f.cwe,
    owasp: f.owasp,
    primary: loc_dto(f.primary),
    message: f.message,
    snippet: f.snippet,
    fingerprint: f.fingerprint,
  }
}

///|
fn warning_dto(w : @core.ParseWarning) -> WarningDto {
  { path: w.path, line: w.line, column: w.column, message: w.message, }
}

///|
/// Build the serializable report DTO. Exposed so tests can assert on structure.
pub fn report_dto(result : @core.ScanResult) -> ReportDto {
  {
    version: ANALYZER_VERSION,
    stats: {
      files_scanned: result.stats.files_scanned,
      files_skipped: result.stats.files_skipped,
      bytes_scanned: result.stats.bytes_scanned,
      raw_hits: result.stats.raw_hits,
    },
    warnings: result.warnings.map(warning_dto),
    skipped_files: result.skipped_files,
    findings: result.findings.map(finding_dto),
  }
}

///|
/// Compact JSON, one line, fixed key order.
pub fn render_json(result : @core.ScanResult) -> String {
  @json.to_json(report_dto(result)).stringify()
}

///|
fn severity_count(
  findings : Array[@core.Finding],
  sev : @core.Severity,
) -> Int32 {
  let mut n = 0
  for f in findings {
    if f.severity == sev {
      n += 1
    }
  }
  n
}

///|
/// Human summary for stdout. Every line is deterministic so cram can assert it.
pub fn render_console(result : @core.ScanResult) -> String {
  let lines : Array[String] = []
  lines.push("\{PRODUCT_NAME} \{ANALYZER_VERSION}")
  lines.push(
    "files: \{result.stats.files_scanned} scanned, \{result.stats.files_skipped} skipped, \{result.stats.raw_hits} raw hits",
  )
  lines.push(
    "findings: \{result.findings.length()} (critical \{severity_count(result.findings, @core.Critical)}, high \{severity_count(result.findings, @core.High)}, medium \{severity_count(result.findings, @core.Medium)}, low \{severity_count(result.findings, @core.Low)}, info \{severity_count(result.findings, @core.Info)})",
  )
  for f in result.findings {
    lines.push(
      "\{f.primary.path}:\{f.primary.line}:\{f.primary.column} \{f.rule_id} [\{@core.severity_name(f.severity)}] \{f.message}",
    )
  }
  lines.push("warnings: \{result.warnings.length()}")
  for w in result.warnings {
    lines.push("\{w.path}:\{w.line}:\{w.column} \{w.message}")
  }
  lines.join("\n")
}

///|
fn xml_escape(s : String) -> String {
  let parts : Array[String] = []
  for c in s {
    if c == '&' {
      parts.push("&amp;")
    } else if c == '<' {
      parts.push("&lt;")
    } else if c == '>' {
      parts.push("&gt;")
    } else if c == '"' {
      parts.push("&quot;")
    } else if c == '\'' {
      parts.push("&apos;")
    } else {
      parts.push("\{c}")
    }
  }
  parts.join("")
}

///|
/// Minimal JUnit XML: one testcase per finding, failures carry the message and
/// the matched snippet as CDATA-free text.
pub fn render_junit(result : @core.ScanResult) -> String {
  let out : Array[String] = []
  out.push("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
  out.push("<testsuites>")
  out.push(
    "  <testsuite name=\"sast\" tests=\"\{result.findings.length()}\" failures=\"\{result.findings.length()}\" errors=\"0\" skipped=\"0\">",
  )
  for f in result.findings {
    let name = "\{f.primary.path}:\{f.primary.line}:\{f.primary.column}"
    out.push(
      "    <testcase classname=\"\{xml_escape(f.rule_id)}\" name=\"\{xml_escape(name)}\">",
    )
    out.push("      <failure message=\"\{xml_escape(f.message)}\">")
    out.push("        \{xml_escape(f.snippet)}")
    out.push("      </failure>")
    out.push("    </testcase>")
  }
  out.push("  </testsuite>")
  out.push("</testsuites>")
  out.join("\n")
}
