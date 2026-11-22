// The analysis entry points are frozen in S4a; the CFG/dataflow body lands in S4b.
//
// While the body is unimplemented, every call returns `NotApplicable` ("no
// opinion"). That is the only safe default: wiring an unfinished analysis must
// never prune findings or claim confirmation.

///|
/// Confirm (or refute) one hit using the taint manifest of its language.
///
/// Contract for S4b:
/// - `NotApplicable` -> finding unchanged (no language block, or rule is not a sink)
/// - `Confirmed`     -> finding keeps severity, `confidence` becomes `High`
/// - `Sanitized` / `NoSource` -> finding is dropped or downgraded to `Low`
pub fn analyze(
  parsed : @parser.ParsedFile,
  hit : @core.RawHit,
  lang : LanguageTaint,
) -> TaintResult {
  let _ = parsed
  let _ = hit
  match sink_for(lang, hit.rule_id) {
    None =>
      no_opinion(
        "rule '\{hit.rule_id}' is not a taint sink for '\{lang.language}'",
      )
    Some(sink) => {
      let capture = if sink.capture.length() == 0 {
        "<primary>"
      } else {
        sink.capture
      }
      no_opinion(
        "taint analysis not implemented yet (S4b); declared sink capture '\{capture}'",
      )
    }
  }
}

///|
/// Convenience wrapper used by the orchestrator: resolve the language block first,
/// and treat "language not configured" as no opinion.
pub fn analyze_with_spec(
  parsed : @parser.ParsedFile,
  hit : @core.RawHit,
  spec : TaintSpec,
) -> TaintResult {
  match for_language(spec, parsed.language) {
    None =>
      no_opinion("no taint configuration for language '\{parsed.language}'")
    Some(lang) => analyze(parsed, hit, lang)
  }
}
