/// Rule-set level validation: ID naming, uniqueness, language keys, predicate shape.
/// Query compilation and capture-name checks live in `apps/rules-validate`
/// because they need the grammar packages.

///|
/// Language registration keys from the MVP spec §1.3.
pub fn registered_languages() -> Array[String] {
  ["javascript", "typescript", "tsx", "python", "java", "json", "moonbit"]
}

///|
fn id_prefix(lang : String) -> String? {
  match lang {
    "javascript" => Some("JS")
    "typescript" => Some("TS")
    "tsx" => Some("TS")
    "python" => Some("PY")
    "java" => Some("JAVA")
    "json" => Some("CFG")
    "moonbit" => Some("MB")
    _ => None
  }
}

///|
fn is_registered(lang : String) -> Bool {
  for l in registered_languages() {
    if l == lang {
      return true
    }
  }
  false
}

///|
/// Check that an ID has the form `<PREFIX><3 digits>` for its language.
pub fn valid_rule_id(id : String, lang : String) -> Bool {
  guard id_prefix(lang) is Some(prefix) else { return false }
  guard id.has_prefix(prefix) else { return false }
  let digits = match id.strip_prefix(prefix) {
    Some(sv) => sv.to_owned()
    None => return false
  }
  guard digits.length() == 3 else { return false }
  for c in digits {
    guard c >= '0' && c <= '9' else { return false }
  }
  true
}

///|
/// Validate a full rule set. Raises `RuleError` on the first problem found.
pub fn validate_rule_set(rules : Array[Rule]) -> Unit raise RuleError {
  let seen : Map[String, Int32] = Map([])
  let mut i = 0
  while i < rules.length() {
    let r = rules[i]
    let path = "/\{i}"

    guard is_registered(r.language) else {
      fail(
        "\{path}/language",
        "unknown language '\{r.language}', expected one of \{registered_languages().join(", ")}",
      )
      return
    }
    guard valid_rule_id(r.id, r.language) else {
      let prefix = match id_prefix(r.language) {
        Some(p) => p
        None => "?"
      }
      fail(
        "\{path}/id",
        "rule ID '\{r.id}' does not match expected form '\{prefix}NNN'",
      )
      return
    }
    match seen.get(r.id) {
      Some(first) =>
        fail(
          "\{path}/id",
          "duplicate rule ID '\{r.id}' (first seen at index \{first})",
        )
      None => seen.set(r.id, i)
    }

    guard r.query.length() > 0 else {
      fail("\{path}/query", "query must not be empty")
      return
    }

    for p in r.predicates {
      guard p.capture.length() > 0 else {
        fail("\{path}/predicates", "predicate capture name must not be empty")
        return
      }
    }
    i += 1
  }
}
