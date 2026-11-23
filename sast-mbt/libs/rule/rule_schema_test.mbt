///|
/// Schema negative cases for the rule parser: wrong JSON types must fail at the
/// exact JSON pointer instead of being coerced, because a coerced rule would scan
/// with different semantics than its author intended.

///|
/// A schema-valid rule body used as the base for every negative case.
const RULE_BODY = "{\"id\":\"JS001\",\"language\":\"javascript\",\"severity\":\"high\",\"cwe\":[95],\"owasp\":[\"A03:2021\"],\"query\":\"(identifier) @x\",\"predicates\":[],\"message\":\"m\",\"enabled\":true}"

///|
fn check_rule_error(
  json_text : String,
  want_path : String,
  want_msg : String,
) -> Unit raise {
  let json = @json.parse(json_text)
  let mut caught = false
  try {
    let _r = @rule.parse_rule(json)
  } catch {
    @rule.RuleError(path~, message~) => {
      caught = true
      assert_eq(path, want_path)
      assert_eq(message, want_msg)
    }
  }
  assert_true(caught)
}

///|
test "schema: string fields reject numbers and objects" {
  check_rule_error(
    RULE_BODY.replace(old="\"language\":\"javascript\"", new="\"language\":42"),
    "/language",
    "expected string",
  )
  check_rule_error(
    RULE_BODY.replace(old="\"id\":\"JS001\"", new="\"id\":{\"a\":1}"),
    "/id",
    "expected string",
  )
}

///|
test "schema: missing required field is reported at its pointer" {
  let json = "{\"language\":\"javascript\",\"severity\":\"high\"," +
    "\"cwe\":[95],\"owasp\":[\"A03:2021\"],\"query\":\"(identifier) @x\"," +
    "\"predicates\":[],\"message\":\"m\",\"enabled\":true}"
  check_rule_error(json, "/id", "missing required field")
}

///|
test "schema: boolean field rejects strings" {
  check_rule_error(
    RULE_BODY.replace(old="\"enabled\":true", new="\"enabled\":\"yes\""),
    "/enabled",
    "expected boolean",
  )
}

///|
test "schema: string array rejects non-array and non-string elements" {
  check_rule_error(
    RULE_BODY.replace(old="\"owasp\":[\"A03:2021\"]", new="\"owasp\":\"A03\""),
    "/owasp",
    "expected array of strings",
  )
  check_rule_error(
    RULE_BODY.replace(old="\"owasp\":[\"A03:2021\"]", new="\"owasp\":[1]"),
    "/owasp/0",
    "expected string",
  )
}

///|
test "schema: integer array rejects non-array, floats and strings" {
  check_rule_error(
    RULE_BODY.replace(old="\"cwe\":[95]", new="\"cwe\":95"),
    "/cwe",
    "expected array of integers",
  )
  check_rule_error(
    RULE_BODY.replace(old="\"cwe\":[95]", new="\"cwe\":[1.5]"),
    "/cwe/0",
    "expected integer",
  )
  check_rule_error(
    RULE_BODY.replace(old="\"cwe\":[95]", new="\"cwe\":[\"x\"]"),
    "/cwe/0",
    "expected integer",
  )
}

///|
test "schema: predicates must be an array of objects" {
  check_rule_error(
    RULE_BODY.replace(old="\"predicates\":[]", new="\"predicates\":\"nope\""),
    "/predicates",
    "expected array of predicate objects",
  )
  check_rule_error(
    RULE_BODY.replace(old="\"predicates\":[]", new="\"predicates\":[1]"),
    "/predicates/0",
    "expected object",
  )
}

///|
test "schema: top-level must be an array of rule objects" {
  let object_top = @json.parse("{\"id\":\"JS001\"}")
  let mut caught = false
  try {
    let _rules = @rule.parse_rules(object_top)
  } catch {
    @rule.RuleError(path~, message~) => {
      caught = true
      assert_eq(path, "")
      assert_eq(message, "expected top-level array of rules")
    }
  }
  assert_true(caught)
  let nested = @json.parse("[1]")
  let mut caught_nested = false
  try {
    let _rules = @rule.parse_rules(nested)
  } catch {
    @rule.RuleError(path~, message~) => {
      caught_nested = true
      assert_eq(path, "/0")
      assert_eq(message, "expected rule object")
    }
  }
  assert_true(caught_nested)
}

///|
test "validate: rule ID prefixes cover every registered language" {
  assert_true(@rule.valid_rule_id("JS001", "javascript"))
  assert_true(@rule.valid_rule_id("TS001", "typescript"))
  assert_true(@rule.valid_rule_id("TS001", "tsx"))
  assert_true(@rule.valid_rule_id("PY001", "python"))
  assert_true(@rule.valid_rule_id("JAVA001", "java"))
  assert_true(@rule.valid_rule_id("CFG001", "json"))
  // unknown language, wrong prefix, wrong digit count, non-digits
  assert_true(!@rule.valid_rule_id("JS001", "cobol"))
  assert_true(!@rule.valid_rule_id("PY001", "javascript"))
  assert_true(!@rule.valid_rule_id("JS01", "javascript"))
  assert_true(!@rule.valid_rule_id("JS0A1", "javascript"))
}

///|
test "validate: empty query and empty predicate capture are rejected" {
  let base = @rule.parse_rule(@json.parse(RULE_BODY))
  let no_query : @rule.Rule = { ..base, query: "", }
  let mut caught_query = false
  @rule.validate_rule_set([no_query]) catch {
    @rule.RuleError(path~, message~) => {
      caught_query = true
      assert_eq(path, "/0/query")
      assert_eq(message, "query must not be empty")
    }
  }
  assert_true(caught_query)
  let bad_pred : @rule.Rule = {
    ..base,
    predicates: [{ kind: @rule.TextEquals, capture: "", value: "eval", }],
  }
  let mut caught_pred = false
  @rule.validate_rule_set([bad_pred]) catch {
    @rule.RuleError(path~, message~) => {
      caught_pred = true
      assert_eq(path, "/0/predicates")
      assert_eq(message, "predicate capture name must not be empty")
    }
  }
  assert_true(caught_pred)
}
