///|
fn sample_spec_json() -> String {
  "{\"version\":\"1.0.0\",\"languages\":[{\"language\":\"javascript\",\"sources\":[{\"name\":\"http_query\",\"node_kind\":\"member_expression\",\"text_contains\":\"req.query\"}],\"sanitizers\":[{\"name\":\"escape_html\",\"callee_contains\":\"escapeHtml\"}],\"sinks\":[{\"rule_id\":\"JS001\",\"capture\":\"arg\"}]}]}"
}

///|
fn parse_or_abort(text : String) -> @taint.TaintSpec {
  match (Some(@taint.parse_spec(@json.parse(text))) catch { _ => None }) {
    Some(spec) => spec
    None => abort("spec should parse")
  }
}

///|
test "spec: parses the documented schema" {
  let spec = parse_or_abort(sample_spec_json())
  assert_eq(spec.version, "1.0.0")
  assert_eq(@taint.supported_languages(spec), ["javascript"])
  let lang = @taint.for_language(spec, "javascript").unwrap()
  assert_eq(lang.sources.length(), 1)
  assert_eq(lang.sources[0].name, "http_query")
  assert_eq(lang.sources[0].node_kind, "member_expression")
  assert_eq(lang.sanitizers[0].callee_contains, "escapeHtml")
  let sink = @taint.sink_for(lang, "JS001").unwrap()
  assert_eq(sink.capture, "arg")
  assert_true(@taint.sink_for(lang, "JS999") is None)
}

///|
test "spec: verdict names are stable" {
  assert_eq(@taint.verdict_name(@core.Confirmed), "confirmed")
  assert_eq(@taint.verdict_name(@core.Sanitized), "sanitized")
  assert_eq(@taint.verdict_name(@core.NoSource), "no-source")
  assert_eq(@taint.verdict_name(@core.NotApplicable), "not-applicable")
}

///|
test "validate: rejects an unknown sink rule id" {
  let spec = parse_or_abort(sample_spec_json())
  let err = try {
    @taint.validate_spec(spec, ["PY001"])
    ""
  } catch {
    @taint.TaintSpecError(message~) => message
  }
  assert_true(err.contains("unknown rule 'JS001'"))
}

///|
test "validate: accepts a consistent spec" {
  let spec = parse_or_abort(sample_spec_json())
  @taint.validate_spec(spec, ["JS001", "PY001"])
}

///|
test "validate: rejects duplicate language and empty version" {
  let dup = parse_or_abort(
    "{\"version\":\"1.0.0\",\"languages\":[{\"language\":\"javascript\",\"sources\":[],\"sanitizers\":[],\"sinks\":[]},{\"language\":\"javascript\",\"sources\":[],\"sanitizers\":[],\"sinks\":[]}]}",
  )
  let dup_err = try {
    @taint.validate_spec(dup, [])
    ""
  } catch {
    @taint.TaintSpecError(message~) => message
  }
  assert_true(dup_err.contains("duplicate language 'javascript'"))
  let empty = parse_or_abort(
    "{\"version\":\"\",\"languages\":[{\"language\":\"javascript\",\"sources\":[],\"sanitizers\":[],\"sinks\":[]}]}",
  )
  let empty_err = try {
    @taint.validate_spec(empty, [])
    ""
  } catch {
    @taint.TaintSpecError(message~) => message
  }
  assert_true(empty_err.contains("'version' must not be empty"))
}

///|
test "validate: rejects duplicate source names inside a language" {
  let spec = parse_or_abort(
    "{\"version\":\"1.0.0\",\"languages\":[{\"language\":\"javascript\",\"sources\":[{\"name\":\"q\",\"node_kind\":\"identifier\",\"text_contains\":\"a\"},{\"name\":\"q\",\"node_kind\":\"identifier\",\"text_contains\":\"b\"}],\"sanitizers\":[],\"sinks\":[]}]}",
  )
  let err = try {
    @taint.validate_spec(spec, [])
    ""
  } catch {
    @taint.TaintSpecError(message~) => message
  }
  assert_true(err.contains("duplicate source name 'q'"))
}

///|
test "analyze: unimplemented analysis never has an opinion" {
  let lang = @taint.for_language(
    parse_or_abort(sample_spec_json()),
    "javascript",
  ).unwrap()
  let parsed = @parser.parse(
    @parser.spec_for_language("javascript").unwrap(),
    "eval(userInput);\n",
    "a.js",
  )
  let hit : @core.RawHit = {
    rule_id: "JS001",
    language: "javascript",
    severity: @core.High,
    cwe: [95],
    owasp: ["A03:2021"],
    message: "m",
    primary: { path: "a.js", line: 1, column: 1, byte_offset: 0, },
    snippet: "eval",
    captures: Map([]),
    taint: @core.NotApplicable,
  }
  let result = @taint.analyze(parsed, hit, lang)
  assert_eq(result.verdict, @core.NotApplicable)
  assert_true(result.detail.contains("not implemented"))
  assert_true(result.source is None)
  // A rule that is not declared as a sink is also no-opinion, with a different reason.
  let other : @core.RawHit = {
    rule_id: "JS999",
    language: "javascript",
    severity: @core.High,
    cwe: [],
    owasp: [],
    message: "m",
    primary: { path: "a.js", line: 1, column: 1, byte_offset: 0, },
    snippet: "x",
    captures: Map([]),
    taint: @core.NotApplicable,
  }
  let other_result = @taint.analyze(parsed, other, lang)
  assert_eq(other_result.verdict, @core.NotApplicable)
  assert_true(other_result.detail.contains("not a taint sink"))
}

///|
/// Reads (ids, id -> language) from the shipped rules.json without depending on
/// the `rule` package (keeps this package's dependency surface minimal).
async fn rule_index() -> (Array[String], Map[String, String]) {
  let text = @fs.read_file("../../rulepacks/official/rules.json").text()
  let ids : Array[String] = []
  let by_id : Map[String, String] = Map([])
  let items = match @json.parse(text) {
    @json.Array(arr) => arr
    _ => abort("rules.json must be a JSON array")
  }
  for item in items {
    let obj = match item {
      @json.Object(o) => o
      _ => abort("rules.json entries must be objects")
    }
    let id = match obj.get("id") {
      Some(@json.String(s)) => s
      _ => abort("rule without string id")
    }
    let lang = match obj.get("language") {
      Some(@json.String(s)) => s
      _ => abort("rule without string language")
    }
    ids.push(id)
    by_id.set(id, lang)
  }
  (ids, by_id)
}

///|
async test "manifest: shipped taint.json is consistent with the rule pack" {
  let (rule_ids, by_id) = rule_index()
  let text = @fs.read_file("../../rulepacks/official/taint.json").text()
  let spec = @taint.parse_spec(@json.parse(text))
  @taint.validate_spec(spec, rule_ids)
  // Every sink must point at a rule of the same language, otherwise taint could
  // never run for it (the file language block would not match).
  let mut sink_count = 0
  for lang in spec.languages {
    for sink in lang.sinks {
      let rule_lang = by_id.get(sink.rule_id).unwrap()
      assert_eq(rule_lang, lang.language)
      sink_count += 1
    }
  }
  assert_true(sink_count >= 10)
  // Coverage sanity: the four code languages that carry injection rules are present.
  let covered = @taint.supported_languages(spec)
  for want in ["javascript", "typescript", "python", "java"] {
    assert_true(covered.contains(want))
  }
}
