///|
/// Manifest validation guards the failure mode that motivated S4a: a typo in a
/// sink's rule id would silently disable taint for that rule, so every schema
/// violation must be a hard error with a locatable message.

///|
fn lang(
  language : String,
  sources : Array[@taint.TaintSourceRule],
  sanitizers : Array[@taint.SanitizerRule],
  sinks : Array[@taint.SinkRule],
) -> @taint.LanguageTaint {
  { language, sources, sanitizers, sinks, }
}

///|
fn spec(
  version : String,
  languages : Array[@taint.LanguageTaint],
) -> @taint.TaintSpec {
  { version, languages, }
}

///|
fn expect_spec_error(
  s : @taint.TaintSpec,
  rule_ids : Array[String],
  want : String,
) -> Unit raise {
  let mut caught = false
  @taint.validate_spec(s, rule_ids) catch {
    @taint.TaintSpecError(message~) => {
      caught = true
      assert_true(message.contains(want))
    }
  }
  assert_true(caught)
}

///|
test "validate_spec: version and languages must not be empty" {
  expect_spec_error(spec("", [lang("javascript", [], [], [])]), [], "'version'")
  expect_spec_error(spec("1.0.0", []), [], "'languages'")
}

///|
test "validate_spec: language blocks must be named and unique" {
  expect_spec_error(
    spec("1.0.0", [lang("", [], [], [])]),
    [],
    "language entry without 'language'",
  )
  expect_spec_error(
    spec("1.0.0", [
      lang("javascript", [], [], []),
      lang("javascript", [], [], []),
    ]),
    [],
    "duplicate language 'javascript'",
  )
}

///|
test "validate_spec: sources need a name, a node kind and unique names" {
  let no_name = @taint.TaintSourceRule::{
    name: "",
    node_kind: "member_expression",
    text_contains: "",
  }
  expect_spec_error(
    spec("1.0.0", [lang("javascript", [no_name], [], [])]),
    [],
    "source without 'name'",
  )
  let no_kind = @taint.TaintSourceRule::{
    name: "http_query",
    node_kind: "",
    text_contains: "",
  }
  expect_spec_error(
    spec("1.0.0", [lang("javascript", [no_kind], [], [])]),
    [],
    "without 'node_kind'",
  )
  let src = @taint.TaintSourceRule::{
    name: "http_query",
    node_kind: "member_expression",
    text_contains: "",
  }
  expect_spec_error(
    spec("1.0.0", [lang("javascript", [src, src], [], [])]),
    [],
    "duplicate source name",
  )
}

///|
test "validate_spec: sanitizers need a name, a needle and unique names" {
  let no_name = @taint.SanitizerRule::{
    name: "",
    callee_contains: "escapeHtml",
  }
  expect_spec_error(
    spec("1.0.0", [lang("javascript", [], [no_name], [])]),
    [],
    "sanitizer without 'name'",
  )
  let no_needle = @taint.SanitizerRule::{
    name: "escape_html",
    callee_contains: "",
  }
  expect_spec_error(
    spec("1.0.0", [lang("javascript", [], [no_needle], [])]),
    [],
    "without 'callee_contains'",
  )
  let san = @taint.SanitizerRule::{
    name: "escape_html",
    callee_contains: "escapeHtml",
  }
  expect_spec_error(
    spec("1.0.0", [lang("javascript", [], [san, san], [])]),
    [],
    "duplicate sanitizer name",
  )
}

///|
test "validate_spec: sinks must name an existing rule exactly once" {
  expect_spec_error(
    spec("1.0.0", [
      lang("javascript", [], [], [{ rule_id: "", capture: "arg", }]),
    ]),
    [],
    "sink without 'rule_id'",
  )
  expect_spec_error(
    spec("1.0.0", [
      lang("javascript", [], [], [{ rule_id: "PY001", capture: "arg", }]),
    ]),
    ["JS001"],
    "sink references unknown rule 'PY001'",
  )
  let sink = @taint.SinkRule::{ rule_id: "JS001", capture: "arg", }
  expect_spec_error(
    spec("1.0.0", [lang("javascript", [], [], [sink, sink])]),
    ["JS001"],
    "duplicate sink for rule 'JS001'",
  )
}

///|
test "validate_spec: a well-formed manifest passes" {
  let sink = @taint.SinkRule::{ rule_id: "JS001", capture: "arg", }
  let src = @taint.TaintSourceRule::{
    name: "http_query",
    node_kind: "member_expression",
    text_contains: "req.query",
  }
  let san = @taint.SanitizerRule::{
    name: "escape_html",
    callee_contains: "escapeHtml",
  }
  @taint.validate_spec(
    spec("1.0.0", [
      lang("javascript", [src], [san], [sink]),
      lang("python", [], [], []),
    ]),
    ["JS001", "PY001"],
  )
  assert_true(true)
}

///|
test "parse_spec: malformed manifest is a TaintSpecError, not a silent empty" {
  let mut caught = false
  try {
    let _ = @taint.parse_spec(@json.parse("{\"version\":1}"))
  } catch {
    @taint.TaintSpecError(message~) => {
      caught = true
      assert_true(message.contains("not valid"))
    }
    _ => ()
  }
  assert_true(caught)
}

///|
test "lookup: for_language, sink_for and supported_languages" {
  let sink = @taint.SinkRule::{ rule_id: "JS001", capture: "arg", }
  let s = spec("1.0.0", [
    lang("javascript", [], [], [sink]),
    lang("python", [], [], []),
  ])
  assert_eq(@taint.supported_languages(s), ["javascript", "python"])
  let js = @taint.for_language(s, "javascript").unwrap()
  assert_true(@taint.sink_for(js, "JS001") is Some(_))
  assert_true(@taint.sink_for(js, "PY001") is None)
  assert_true(@taint.for_language(s, "java") is None)
}
