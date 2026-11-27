///|
fn parse_js(src : String) -> @parser.ParsedFile {
  let spec = @parser.spec_for_language("javascript").unwrap()
  @parser.parse(spec, src, "t.js")
}

///|
fn eval_rule() -> @rule.Rule {
  @rule.Rule::{
    id: "JS001",
    language: "javascript",
    severity: @core.High,
    cwe: [95],
    owasp: ["A03:2021"],
    query: "(call_expression function: (identifier) @callee arguments: (arguments . (_) @arg)) @call",
    predicates: [
      @rule.PredicateSpec::{
        kind: @rule.TextEquals,
        capture: "callee",
        value: "eval",
      },
      @rule.PredicateSpec::{
        kind: @rule.NotHasPrefix,
        capture: "arg",
        value: "\"",
      },
    ],
    message: "Dynamic code execution via eval()",
    enabled: true,
  }
}

///|
test "predicate: all eight kinds evaluate as specified" {
  let value = "eval"
  assert_true(
    @query-engine.eval_predicate(
      @rule.PredicateSpec::{ kind: @rule.TextEquals, capture: "c", value, },
      "eval",
    ),
  )
  assert_true(
    !@query-engine.eval_predicate(
      @rule.PredicateSpec::{ kind: @rule.TextNotEquals, capture: "c", value, },
      "eval",
    ),
  )
  assert_true(
    @query-engine.eval_predicate(
      @rule.PredicateSpec::{ kind: @rule.HasPrefix, capture: "c", value: "ev", },
      "eval",
    ),
  )
  assert_true(
    @query-engine.eval_predicate(
      @rule.PredicateSpec::{
        kind: @rule.NotHasPrefix,
        capture: "c",
        value: "xy",
      },
      "eval",
    ),
  )
  assert_true(
    @query-engine.eval_predicate(
      @rule.PredicateSpec::{ kind: @rule.HasSuffix, capture: "c", value: "al", },
      "eval",
    ),
  )
  assert_true(
    @query-engine.eval_predicate(
      @rule.PredicateSpec::{
        kind: @rule.NotHasSuffix,
        capture: "c",
        value: "zz",
      },
      "eval",
    ),
  )
  assert_true(
    @query-engine.eval_predicate(
      @rule.PredicateSpec::{ kind: @rule.Contains, capture: "c", value: "va", },
      "eval",
    ),
  )
  assert_true(
    @query-engine.eval_predicate(
      @rule.PredicateSpec::{
        kind: @rule.NotContains,
        capture: "c",
        value: "zz",
      },
      "eval",
    ),
  )
}

///|
fn ic(kind : @rule.PredicateKind, value : String) -> @rule.PredicateSpec {
  @rule.PredicateSpec::{ kind, capture: "c", value, }
}

///|
test "predicate: ignore_case variants fold ASCII on both sides" {
  assert_true(
    @query-engine.eval_predicate(ic(@rule.TextEqualsIgnoreCase, "EVAL"), "eval"),
  )
  assert_true(
    !@query-engine.eval_predicate(
      ic(@rule.TextEqualsIgnoreCase, "EVAL"),
      "evalx",
    ),
  )
  // The case-sensitive kind still rejects the same text: opt-in, not a global change.
  assert_true(
    !@query-engine.eval_predicate(ic(@rule.TextEquals, "EVAL"), "eval"),
  )
  assert_true(
    !@query-engine.eval_predicate(
      ic(@rule.TextNotEqualsIgnoreCase, "EVAL"),
      "eval",
    ),
  )
  assert_true(
    @query-engine.eval_predicate(
      ic(@rule.TextNotEqualsIgnoreCase, "EVAL"),
      "evalx",
    ),
  )
  assert_true(
    @query-engine.eval_predicate(
      ic(@rule.HasPrefixIgnoreCase, "RE"),
      "request.body",
    ),
  )
  assert_true(
    @query-engine.eval_predicate(
      ic(@rule.NotHasPrefixIgnoreCase, "RE"),
      "payload",
    ),
  )
  assert_true(
    @query-engine.eval_predicate(
      ic(@rule.HasSuffixIgnoreCase, "BODY"),
      "request.Body",
    ),
  )
  assert_true(
    @query-engine.eval_predicate(
      ic(@rule.NotHasSuffixIgnoreCase, "BODY"),
      "request.head",
    ),
  )
  assert_true(
    @query-engine.eval_predicate(
      ic(@rule.ContainsIgnoreCase, "ORIGIN"),
      "allowedOrigin",
    ),
  )
  assert_true(
    @query-engine.eval_predicate(
      ic(@rule.NotContainsIgnoreCase, "ORIGIN"),
      "allowedHost",
    ),
  )
  // ASCII-only by design: non-ASCII letters are not locale-folded.
  assert_true(
    !@query-engine.eval_predicate(
      ic(@rule.TextEqualsIgnoreCase, "STRASSE"),
      "straße",
    ),
  )
}

///|
/// Synthetic source to exercise the engine; real rules pick the case kind to
/// match the language's identifier semantics.
fn eval_rule_ignore_case() -> @rule.Rule {
  @rule.Rule::{
    id: "JS011",
    language: "javascript",
    severity: @core.High,
    cwe: [],
    owasp: [],
    query: "(call_expression function: (identifier) @callee arguments: (arguments . (_) @arg)) @call",
    predicates: [
      @rule.PredicateSpec::{
        kind: @rule.TextEqualsIgnoreCase,
        capture: "callee",
        value: "EVAL",
      },
    ],
    message: "case-insensitive dynamic code execution",
    enabled: true,
  }
}

///|
test "run_rules: ignore_case predicate matches either letter case" {
  let parsed = parse_js("eval(userInput);\nEVAL(userInput);\n")
  let result = @query-engine.run_rules(parsed, [eval_rule_ignore_case()])
  assert_eq(result.failures.length(), 0)
  assert_eq(result.hits.length(), 2)
  assert_eq(result.hits[0].primary.line, 1)
  assert_eq(result.hits[1].primary.line, 2)
}

///|
test "predicate: a missing capture fails closed" {
  let caps : Map[String, String] = Map([])
  caps.set("callee", "eval")
  let preds = [
    @rule.PredicateSpec::{
      kind: @rule.TextEquals,
      capture: "callee",
      value: "eval",
    },
    @rule.PredicateSpec::{
      kind: @rule.NotHasPrefix,
      capture: "arg",
      value: "\"",
    },
  ]
  assert_true(!@query-engine.eval_predicates(preds, caps))
}

///|
test "run_rules: one eval call produces one raw hit with P0-compatible location" {
  let parsed = parse_js("const a = 1;\neval(userInput);\n")
  let result = @query-engine.run_rules(parsed, [eval_rule()])
  assert_eq(result.failures.length(), 0)
  assert_eq(result.hits.length(), 1)
  let hit = result.hits[0]
  assert_eq(hit.rule_id, "JS001")
  // S4b: every hit carries its file language and starts with no taint opinion.
  assert_eq(hit.language, "javascript")
  assert_eq(hit.taint, @core.NotApplicable)
  assert_eq(hit.severity, @core.High)
  assert_eq(hit.primary.line, 2)
  assert_eq(hit.primary.column, 1)
  assert_eq(hit.primary.byte_offset, 13)
  assert_eq(hit.snippet, "eval")
  assert_eq(hit.captures.get("callee"), Some("eval"))
  assert_eq(hit.captures.get("arg"), Some("userInput"))
}

///|
test "run_rules: string literal argument is rejected by not_has_prefix" {
  let parsed = parse_js("eval(\"console.log(1)\");\n")
  let result = @query-engine.run_rules(parsed, [eval_rule()])
  assert_eq(result.hits.length(), 0)
  assert_eq(result.failures.length(), 0)
}

///|
test "run_rules: non-eval callee yields no hit" {
  let parsed = parse_js("console.log(x);\nfoo(x);\n")
  let result = @query-engine.run_rules(parsed, [eval_rule()])
  assert_eq(result.hits.length(), 0)
}

///|
test "run_rules: disabled and other-language rules are skipped" {
  let parsed = parse_js("eval(userInput);\n")
  let disabled = @rule.Rule::{
    id: "JS002",
    language: "javascript",
    severity: @core.High,
    cwe: [],
    owasp: [],
    query: "(call_expression function: (identifier) @callee) @call",
    predicates: [],
    message: "disabled rule",
    enabled: false,
  }
  let python_rule = @rule.Rule::{
    id: "PY001",
    language: "python",
    severity: @core.High,
    cwe: [],
    owasp: [],
    query: "(call) @call",
    predicates: [],
    message: "python rule",
    enabled: true,
  }
  let result = @query-engine.run_rules(parsed, [disabled, python_rule])
  assert_eq(result.hits.length(), 0)
  assert_eq(result.failures.length(), 0)
}

///|
test "run_rules: broken query is reported as a failure, not a crash" {
  let parsed = parse_js("eval(userInput);\n")
  let broken = @rule.Rule::{
    id: "JS009",
    language: "javascript",
    severity: @core.High,
    cwe: [],
    owasp: [],
    query: "(this_node_does_not_exist) @x",
    predicates: [],
    message: "broken",
    enabled: true,
  }
  let result = @query-engine.run_rules(parsed, [broken])
  assert_eq(result.hits.length(), 0)
  assert_true(result.failures.length() > 0)
  assert_eq(result.failures[0].rule_id, "JS009")
}

///|
test "run_rules: unparsable file yields no hits and no failures" {
  let parsed = parse_js("function f() {\n")
  assert_true(parsed.warnings.length() > 0)
  let result = @query-engine.run_rules(parsed, [eval_rule()])
  assert_eq(result.failures.length(), 0)
  assert_eq(result.hits.length(), 0)
}

///|
test "eval_predicates: a missing capture fails closed" {
  let preds : Array[@rule.PredicateSpec] = [
    @rule.PredicateSpec::{
      kind: @rule.TextEquals,
      capture: "callee",
      value: "eval",
    },
  ]
  assert_true(!@query-engine.eval_predicates(preds, Map([])))
  assert_true(@query-engine.eval_predicates(preds, Map([("callee", "eval")])))
  assert_true(!@query-engine.eval_predicates(preds, Map([("callee", "exec")])))
  // Every predicate must pass; one failure rejects the match.
  let two : Array[@rule.PredicateSpec] = [
    @rule.PredicateSpec::{
      kind: @rule.TextEquals,
      capture: "callee",
      value: "eval",
    },
    @rule.PredicateSpec::{
      kind: @rule.HasPrefix,
      capture: "arg",
      value: "req",
    },
  ]
  assert_true(
    !@query-engine.eval_predicates(two, Map([("callee", "eval"), ("arg", "x")])),
  )
  assert_true(
    @query-engine.eval_predicates(
      two,
      Map([("callee", "eval"), ("arg", "req.body")]),
    ),
  )
}
