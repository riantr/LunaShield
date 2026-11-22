///|
/// Strict, path-aware JSON decoding of rules.
/// We decode manually because `@json.FromJson` silently ignores unknown fields,
/// which would let rule typos pass `rules-validate`.
fn fail(path : String, message : String) -> Unit raise RuleError {
  raise RuleError(path~, message~)
}

///|
fn rule_keys() -> Array[String] {
  [
    "id", "language", "severity", "cwe", "owasp", "query", "predicates", "message",
    "enabled",
  ]
}

///|
fn predicate_keys() -> Array[String] {
  ["kind", "capture", "value"]
}

///|
fn reject_unknown_keys(
  obj : Map[String, @json.Json],
  allowed : Array[String],
  path : String,
) -> Unit raise RuleError {
  for (key, _) in obj.iter() {
    let mut known = false
    for k in allowed {
      if key == k {
        known = true
      }
    }
    if !known {
      let full = if path == "" { "/\{key}" } else { "\{path}/\{key}" }
      fail(full, "unknown field")
    }
  }
}

///|
fn get_required(
  obj : Map[String, @json.Json],
  key : String,
  path : String,
) -> @json.Json raise RuleError {
  match obj.get(key) {
    Some(v) => v
    None => {
      fail("\{path}/\{key}", "missing required field")
      @json.Json::null()
    }
  }
}

///|
fn get_string(
  obj : Map[String, @json.Json],
  key : String,
  path : String,
) -> String raise RuleError {
  let v = get_required(obj, key, path)
  if v is @json.String(s) {
    s
  } else {
    fail("\{path}/\{key}", "expected string")
    ""
  }
}

///|
fn get_bool_field(
  obj : Map[String, @json.Json],
  key : String,
  path : String,
) -> Bool raise RuleError {
  let v = get_required(obj, key, path)
  match v {
    @json.True => true
    @json.False => false
    _ => {
      fail("\{path}/\{key}", "expected boolean")
      false
    }
  }
}

///|
fn get_string_array(
  obj : Map[String, @json.Json],
  key : String,
  path : String,
) -> Array[String] raise RuleError {
  let v = get_required(obj, key, path)
  guard v is @json.Array(arr) else {
    fail("\{path}/\{key}", "expected array of strings")
    return []
  }
  let out : Array[String] = []
  let mut i = 0
  while i < arr.length() {
    if arr[i] is @json.String(s) {
      out.push(s)
    } else {
      fail("\{path}/\{key}/\{i}", "expected string")
    }
    i += 1
  }
  out
}

///|
fn get_int_array(
  obj : Map[String, @json.Json],
  key : String,
  path : String,
) -> Array[Int32] raise RuleError {
  let v = get_required(obj, key, path)
  guard v is @json.Array(arr) else {
    fail("\{path}/\{key}", "expected array of integers")
    return []
  }
  let out : Array[Int32] = []
  let mut i = 0
  while i < arr.length() {
    if arr[i] is @json.Number(n, ..) {
      guard n == n.floor() else {
        fail("\{path}/\{key}/\{i}", "expected integer")
        return []
      }
      out.push(n.to_int())
    } else {
      fail("\{path}/\{key}/\{i}", "expected integer")
    }
    i += 1
  }
  out
}

///|
fn parse_predicate(
  value : @json.Json,
  path : String,
) -> PredicateSpec raise RuleError {
  guard value is @json.Object(obj) else {
    fail(path, "expected object")
    return PredicateSpec::{ kind: TextEquals, capture: "", value: "", }
  }
  reject_unknown_keys(obj, predicate_keys(), path)
  let kind_str = get_string(obj, "kind", path)
  let kind = match predicate_kind_from_string(kind_str) {
    Some(k) => k
    None => {
      fail(
        "\{path}/kind",
        "unknown predicate kind '\{kind_str}', allowed: \{predicate_kind_names().join(", ")}",
      )
      TextEquals
    }
  }
  let capture = get_string(obj, "capture", path)
  let value_str = get_string(obj, "value", path)
  PredicateSpec::{ kind, capture, value: value_str, }
}

///|
/// Parse a rule from a JSON value. Raises `RuleError` with a pointer path on any problem.
pub fn parse_rule(
  value : @json.Json,
  base_path~ : String = "",
) -> Rule raise RuleError {
  guard value is @json.Object(obj) else {
    fail(base_path, "expected rule object")
    return Rule::{
      id: "",
      language: "",
      severity: @core.Info,
      cwe: [],
      owasp: [],
      query: "",
      predicates: [],
      message: "",
      enabled: false,
    }
  }
  reject_unknown_keys(obj, rule_keys(), base_path)

  let id = get_string(obj, "id", base_path)
  let language = get_string(obj, "language", base_path)
  let severity_str = get_string(obj, "severity", base_path)
  let severity = match @core.severity_from_string(severity_str) {
    Some(sv) => sv
    None => {
      fail(
        "\{base_path}/severity",
        "unknown severity '\{severity_str}', expected critical|high|medium|low|info",
      )
      @core.Info
    }
  }
  let cwe = get_int_array(obj, "cwe", base_path)
  let owasp = get_string_array(obj, "owasp", base_path)
  let query = get_string(obj, "query", base_path)
  let message = get_string(obj, "message", base_path)
  let enabled = match obj.get("enabled") {
    Some(_) => get_bool_field(obj, "enabled", base_path)
    None => true
  }

  let predicates_value = get_required(obj, "predicates", base_path)
  guard predicates_value is @json.Array(parr) else {
    fail("\{base_path}/predicates", "expected array of predicate objects")
    return Rule::{
      id,
      language,
      severity,
      cwe,
      owasp,
      query,
      predicates: [],
      message,
      enabled,
    }
  }
  let predicates : Array[PredicateSpec] = []
  let mut i = 0
  while i < parr.length() {
    predicates.push(parse_predicate(parr[i], "\{base_path}/predicates/\{i}"))
    i += 1
  }

  Rule::{
    id,
    language,
    severity,
    cwe,
    owasp,
    query,
    predicates,
    message,
    enabled,
  }
}

///|
/// Parse a whole rulepack `rules.json` (a JSON array of rules).
pub fn parse_rules(value : @json.Json) -> Array[Rule] raise RuleError {
  guard value is @json.Array(arr) else {
    fail("", "expected top-level array of rules")
    return []
  }
  let rules : Array[Rule] = []
  let mut i = 0
  while i < arr.length() {
    rules.push(parse_rule(arr[i], base_path="/\{i}"))
    i += 1
  }
  rules
}
