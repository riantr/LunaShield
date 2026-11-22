// P2-S4a: taint data model and manifest schema (interfaces frozen, analysis stubbed).
//
// Design rule: everything here is *data*. Sources/sanitizers/sinks live in
// `rulepacks/official/taint.json`, never compiled into the engine, so a rule pack
// can be audited and extended without touching MoonBit code.

///|
/// A user-controlled value that may enter a function body.
///
/// Matching is deliberately dumb in v0 (node kind + substring on the node text):
/// no regex, no dynamic code, consistent with the fixed-predicate philosophy of
/// the AST rules.
#derive(Debug, Eq, @json.ToJson, @json.FromJson)
pub(all) struct TaintSourceRule {
  /// Logical name used in reports (`http_param`, `argv`, ...).
  name : String
  /// Tree-sitter node kind the source must parse as (`member_expression`, ...).
  node_kind : String
  /// Substring the node text must contain. Empty means "any node of that kind".
  text_contains : String
}

///|
/// A call that neutralizes taint (escaping, strict parsing, quoting).
#derive(Debug, Eq, @json.ToJson, @json.FromJson)
pub(all) struct SanitizerRule {
  /// Logical name used in reports.
  name : String
  /// Substring the callee text must contain (`escapeHtml`, `parseInt`, ...).
  callee_contains : String
}

///|
/// Declares which detection rules are taint sinks, and where in the match the
/// sink argument sits.
#derive(Debug, Eq, @json.ToJson, @json.FromJson)
pub(all) struct SinkRule {
  /// Rule id from `rules.json` (`JS001`, `PY006`, ...).
  rule_id : String
  /// Capture name holding the sink argument. Empty means "primary capture".
  capture : String
}

///|
/// Per-language taint configuration.
#derive(Debug, Eq, @json.ToJson, @json.FromJson)
pub(all) struct LanguageTaint {
  language : String
  sources : Array[TaintSourceRule]
  sanitizers : Array[SanitizerRule]
  sinks : Array[SinkRule]
}

///|
/// The whole manifest, loaded from `taint.json`.
#derive(Debug, Eq, @json.ToJson, @json.FromJson)
pub(all) struct TaintSpec {
  version : String
  languages : Array[LanguageTaint]
}

///|
/// Alias kept for callers that only import `taint`; the enum itself lives in
/// `core-model` because every `RawHit` carries one.
pub fn verdict_name(v : @core.TaintVerdict) -> String {
  @core.verdict_name(v)
}

///|
/// Verdict plus the locations that produced it (used by SARIF `codeFlows` in S5).
pub(all) struct TaintResult {
  verdict : @core.TaintVerdict
  source : @core.SourceLoc?
  sanitizer : @core.SourceLoc?
  /// Human-readable reason, kept stable for tests and future report fields.
  detail : String
}

///|
pub fn no_opinion(detail : String) -> TaintResult {
  { verdict: NotApplicable, source: None, sanitizer: None, detail, }
}
