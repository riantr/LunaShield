///|
/// M1 acceptance: JSON roundtrip, predicate whitelist, ID naming/uniqueness.
const GOOD_RULE_JSON = "{\"id\":\"JS001\",\"language\":\"javascript\",\"severity\":\"high\",\"cwe\":[95],\"owasp\":[\"A03:2021\"],\"query\":\"(call_expression function: (identifier) @callee)\",\"predicates\":[{\"kind\":\"text_equals\",\"capture\":\"callee\",\"value\":\"eval\"}],\"message\":\"Dynamic code execution\",\"enabled\":true}"

///|
test "parse and serialize a valid rule (JSON roundtrip)" {
  let json1 = @json.parse(GOOD_RULE_JSON)
  let rule1 = @rule.parse_rule(json1)
  assert_eq(rule1.id, "JS001")
  assert_eq(rule1.severity, @core.High)
  assert_eq(rule1.predicates.length(), 1)
  assert_eq(rule1.predicates[0].kind, @rule.TextEquals)
  assert_true(rule1.enabled)

  let emitted = @json.to_json(rule1).stringify()
  let json2 = @json.parse(emitted)
  let rule2 = @rule.parse_rule(json2)
  assert_eq(rule2, rule1)
}

///|
test "unknown predicate kind is rejected at its JSON pointer" {
  let bad = GOOD_RULE_JSON.replace(old="text_equals", new="regex_match")
  let json = @json.parse(bad)
  let mut caught = false
  try {
    let _r = @rule.parse_rule(json)
  } catch {
    e =>
      match e {
        @rule.RuleError(path~, message~) => {
          caught = true
          assert_eq(path, "/predicates/0/kind")
          assert_true(message.contains("regex_match"))
        }
      }
  }
  assert_true(caught)
}

///|
test "unknown top-level field is rejected (derive would silently accept)" {
  let bad = GOOD_RULE_JSON.replace(old="{\"id\"", new="{\"typo\":1,\"id\"")
  let json = @json.parse(bad)
  let mut caught = false
  try {
    let _r = @rule.parse_rule(json)
  } catch {
    e =>
      match e {
        @rule.RuleError(path~, message~) => {
          caught = true
          assert_eq(path, "/typo")
          assert_eq(message, "unknown field")
        }
      }
  }
  assert_true(caught)
}

///|
test "severity whitelist rejects unknown value" {
  let bad = GOOD_RULE_JSON.replace(
    old="\"severity\":\"high\"",
    new="\"severity\":\"unknown\"",
  )
  let json = @json.parse(bad)
  let mut caught = false
  try {
    let _r = @rule.parse_rule(json)
  } catch {
    e =>
      match e {
        @rule.RuleError(path~, ..) => {
          caught = true
          assert_eq(path, "/severity")
        }
      }
  }
  assert_true(caught)
}

///|
test "predicate kind names roundtrip through the whitelist" {
  for name in @rule.predicate_kind_names() {
    match @rule.predicate_kind_from_string(name) {
      Some(k) => assert_eq(@rule.predicate_kind_name(k), name)
      None => abort("whitelist name not accepted: \{name}")
    }
  }
  assert_eq(@rule.predicate_kind_from_string("regex_match"), None)
}

///|
test "rule ID naming follows <PREFIX><NNN> per language" {
  assert_true(@rule.valid_rule_id("JS001", "javascript"))
  assert_true(@rule.valid_rule_id("JAVA010", "java"))
  assert_true(@rule.valid_rule_id("CFG010", "json"))
  assert_true(@rule.valid_rule_id("TS003", "tsx"))
  assert_false(@rule.valid_rule_id("JS1", "javascript"))
  assert_false(@rule.valid_rule_id("PY00X", "python"))
  assert_false(@rule.valid_rule_id("JS001", "python"))
}

///|
test "duplicate rule ID is rejected with pointer path" {
  let json = @json.parse("[\{GOOD_RULE_JSON},\{GOOD_RULE_JSON}]")
  let rules = @rule.parse_rules(json)
  let mut caught = false
  @rule.validate_rule_set(rules) catch {
    e =>
      match e {
        @rule.RuleError(path~, message~) => {
          caught = true
          assert_eq(path, "/1/id")
          assert_true(message.contains("duplicate"))
        }
      }
  }
  assert_true(caught)
}

///|
test "unknown language is rejected" {
  let bad = GOOD_RULE_JSON.replace(
    old="\"language\":\"javascript\"",
    new="\"language\":\"ruby\"",
  )
  let rules = @rule.parse_rules(@json.parse("[\{bad}]"))
  let mut caught = false
  @rule.validate_rule_set(rules) catch {
    e =>
      match e {
        @rule.RuleError(path~, ..) => {
          caught = true
          assert_eq(path, "/0/language")
        }
      }
  }
  assert_true(caught)
}
