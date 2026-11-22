///|
/// Finding severity, ordered from most to least severe.
#derive(Debug, Eq)
pub(all) enum Severity {
  Critical
  High
  Medium
  Low
  Info
}

///|
/// Confidence of a finding. AST-only matches are always `High` in the MVP.
#derive(Debug, Eq)
pub(all) enum Confidence {
  High
  Medium
  Low
}

///|
/// A single source location. `line` and `column` are 1-based.
#derive(Debug, Eq)
pub(all) struct SourceLoc {
  path : String
  line : Int32
  column : Int32
  byte_offset : Int32
}

///|
/// A security finding produced by the analyzer.
#derive(Debug, Eq)
pub(all) struct Finding {
  rule_id : String
  severity : Severity
  confidence : Confidence
  cwe : Array[Int32]
  owasp : Array[String]
  primary : SourceLoc
  related : Array[SourceLoc]
  message : String
  snippet : String
  fingerprint : String
}

///|
/// Verdict of the optional taint stage (P2). Lives in the model because it is
/// carried on every `RawHit`; `libs/taint` only decides the value.
#derive(Debug, Eq)
pub(all) enum TaintVerdict {
  Confirmed
  Sanitized
  NoSource
  NotApplicable
}

///|
/// Stable lowercase name, used in reports and tests.
pub fn verdict_name(v : TaintVerdict) -> String {
  match v {
    Confirmed => "confirmed"
    Sanitized => "sanitized"
    NoSource => "no-source"
    NotApplicable => "not-applicable"
  }
}

///|
/// A rule match that satisfied every predicate, produced by `query-engine` and
/// consumed by `scoring`. Defined here so `scoring` can finish a Finding without
/// depending on the execution layer.
pub(all) struct RawHit {
  rule_id : String
  /// Language key of the file the hit came from (`javascript`, ...), needed by
  /// the taint stage to pick a manifest block.
  language : String
  severity : Severity
  cwe : Array[Int32]
  owasp : Array[String]
  message : String
  primary : SourceLoc
  snippet : String
  captures : Map[String, String]
  /// Taint verdict; `NotApplicable` until the taint stage runs (P2-S4b).
  taint : TaintVerdict
}

///|
/// A recoverable parse-time problem. Does not abort the scan.
#derive(Debug, Eq)
pub(all) struct ParseWarning {
  path : String
  line : Int32
  column : Int32
  message : String
}

///|
/// Counters collected during a scan.
#derive(Debug, Eq)
pub(all) struct ScanStats {
  files_scanned : Int32
  files_skipped : Int32
  bytes_scanned : Int32
  raw_hits : Int32
  duration_ms : Int32
}

///|
/// Complete result of a scan: sorted, deduplicated findings plus diagnostics.
#derive(Debug, Eq)
pub(all) struct ScanResult {
  findings : Array[Finding]
  warnings : Array[ParseWarning]
  skipped_files : Array[String]
  stats : ScanStats
}

///|
/// Numeric rank used by the `--fail-on` gate. Larger means more severe.
pub fn severity_rank(s : Severity) -> Int32 {
  match s {
    Critical => 5
    High => 4
    Medium => 3
    Low => 2
    Info => 1
  }
}

///| Parse a lowercase severity string from rule/config JSON.

///|
/// Returns `None` for unknown values so callers can report a precise error.
pub fn severity_from_string(s : String) -> Severity? {
  match s {
    "critical" => Some(Critical)
    "high" => Some(High)
    "medium" => Some(Medium)
    "low" => Some(Low)
    "info" => Some(Info)
    _ => None
  }
}

///|
/// Stable lowercase name used in reports and rule JSON.
pub fn severity_name(s : Severity) -> String {
  match s {
    Critical => "critical"
    High => "high"
    Medium => "medium"
    Low => "low"
    Info => "info"
  }
}

///|
/// Stable lowercase serialization for Severity (report DTO contract).
pub impl @json.ToJson for Severity with fn to_json(self) -> @json.Json {
  @json.Json::string(severity_name(self))
}

///|
/// Parse a lowercase confidence string from config/report/cached JSON.
/// `None` for unknown values so callers can fall back deliberately.
pub fn confidence_from_string(s : String) -> Confidence? {
  match s {
    "high" => Some(High)
    "medium" => Some(Medium)
    "low" => Some(Low)
    _ => None
  }
}

///|
/// Stable lowercase name used in reports and cached entries.
pub fn confidence_name(c : Confidence) -> String {
  match c {
    High => "high"
    Medium => "medium"
    Low => "low"
  }
}

///|
/// Stable lowercase serialization for Confidence.
pub impl @json.ToJson for Confidence with fn to_json(self) -> @json.Json {
  @json.Json::string(confidence_name(self))
}
