///|
/// Analyzer edge cases that only real (parsed) input can reach: a hit whose
/// byte range points outside the tree, and a sink capture missing from the
/// hit's capture map (the manifest may name a capture the rule never binds).

///|
const EXTRA_TAINT_JSON = "{\"version\":\"1.0.0\",\"languages\":[{\"language\":\"javascript\",\"sources\":[{\"name\":\"http_query\",\"node_kind\":\"member_expression\",\"text_contains\":\"req.query\"}],\"sanitizers\":[],\"sinks\":[{\"rule_id\":\"JS001\",\"capture\":\"arg\"}]}]}"

///|
fn extra_parsed() -> @parser.ParsedFile {
  @parser.parse(
    @parser.spec_for_language("javascript").unwrap(),
    "function f(req) { eval(req.query.x); }\n",
    "a.js",
  )
}

///|
fn extra_hit(byte_offset : Int32, snippet : String) -> @core.RawHit {
  {
    rule_id: "JS001",
    language: "javascript",
    severity: @core.High,
    cwe: [95],
    owasp: ["A03:2021"],
    message: "m",
    primary: { path: "a.js", line: 1, column: 1, byte_offset, },
    snippet,
    captures: Map([]),
    taint: @core.NotApplicable,
  }
}

///|
test "analyze: a missing sink capture falls back to the hit snippet" {
  let spec = @taint.parse_spec(@json.parse(EXTRA_TAINT_JSON)) catch {
    _ => abort("spec must parse")
  }
  // Byte 18 is where `eval` starts in the fixture above.
  let result = @taint.analyze_with_spec(
    extra_parsed(),
    extra_hit(18, "eval"),
    spec,
  )
  // The sink argument text falls back to "eval", whose names never intersect
  // `req.query`, so no source is considered to reach it.
  assert_eq(result.verdict, @core.NoSource)
  assert_true(result.detail.contains("'eval'"))
}
