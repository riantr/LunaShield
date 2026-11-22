// M1 rules-validate: schema + ID/language/whitelist + Query compile + capture-name
// + fixture三件套 + manifest checksum. Exits 0 on success, 2 on any validation error.

///|
/// Primary fixture extension for a language, taken from the single source of
/// truth in `lang-registry` (M2) so the six registrations cannot drift.
fn fixture_extension(lang : String) -> String {
  match @lang.spec_by_id(lang) {
    Some(spec) =>
      if spec.extensions.length() > 0 {
        spec.extensions[0]
      } else {
        "txt"
      }
    None => "txt"
  }
}

///|
/// Collect all query/fixture errors for a rule set.
async fn validate_queries(
  rules : Array[@rule.Rule],
  fixtures_dir : String,
) -> Array[String] {
  let errors : Array[String] = []
  for r in rules {
    let path = r.id
    match @lang.spec_by_id(r.language) {
      None => errors.push("\{path}: no grammar for language '\{r.language}'")
      Some(spec) => {
        let query = @treesitter.Query::new(spec.language(), r.query) catch {
          @treesitter.QueryError(row~, column~, offset~, message~, ..) => {
            errors.push(
              "\{path}: query compile failed at line \{row}, column \{column} (offset \{offset}): \{message}",
            )
            return []
          }
        }
        for p in r.predicates {
          if query.capture_index_for_name(p.capture) is None {
            errors.push(
              "\{path}: predicate capture '@\{p.capture}' not found in query (captures: \{query.capture_names().join(", ")})",
            )
          }
        }
        let ext = fixture_extension(r.language)
        for name in ["positive.\{ext}", "negative.\{ext}", "expected.json"] {
          let fp = "\{fixtures_dir}/\{r.id}/\{name}"
          if !@fs.exists(fp) {
            errors.push("\{path}: missing fixture \{fp}")
          }
        }
      }
    }
  }
  errors
}

///|
async fn read_text(path : String) -> String {
  @fs.read_file(path).text()
}

///|
/// Manifest checksum verification. Returns an error message or empty string.
async fn check_manifest(pack_dir : String) -> String {
  let manifest_path = "\{pack_dir}/manifest.json"
  guard @fs.exists(manifest_path) else { return "missing \{manifest_path}" }
  let manifest_json = @json.parse(read_text(manifest_path)) catch {
    e => return "manifest.json parse error: \{e}"
  }
  guard manifest_json is @json.Object(obj) else {
    return "manifest.json: expected object"
  }
  let rules_file = match obj.get("rules_file") {
    Some(@json.String(s)) => s
    _ => return "manifest.json: missing rules_file"
  }
  let expected = match obj.get("rules_sha256") {
    Some(@json.String(s)) => s
    _ => return "manifest.json: missing rules_sha256"
  }
  let rules_path = "\{pack_dir}/\{rules_file}"
  guard @fs.exists(rules_path) else { return "missing \{rules_path}" }
  let bytes = @utf8.encode(read_text(rules_path))
  let actual = @bithash.hex_encode(@bithash.sha256_raw(bytes))
  if actual != expected {
    return "rules.json SHA-256 mismatch: expected \{expected}, got \{actual}"
  }
  ""
}

///|
/// Validate a rulepack directory. Returns all error messages (empty means OK).
async fn validate_pack(
  pack_dir : String,
  fixtures_dir : String,
) -> Array[String] {
  let errors : Array[String] = []
  let manifest_error = check_manifest(pack_dir)
  if manifest_error.length() > 0 {
    errors.push(manifest_error)
    return errors
  }
  let rules_path = "\{pack_dir}/rules.json"
  let json = @json.parse(read_text(rules_path)) catch {
    e => {
      errors.push("rules.json parse error: \{e}")
      return errors
    }
  }
  let rules = @rule.parse_rules(json) catch {
    e =>
      match e {
        @rule.RuleError(path~, message~) => {
          errors.push("rules.json\{path}: \{message}")
          return errors
        }
      }
  }
  @rule.validate_rule_set(rules) catch {
    e =>
      match e {
        @rule.RuleError(path~, message~) =>
          errors.push("rules\{path}: \{message}")
      }
  }
  for e in validate_queries(rules, fixtures_dir) {
    errors.push(e)
  }
  errors
}

///|
async fn main {
  let args = @env.args()
  let pack_dir = if args.length() >= 2 { args[1] } else { "rulepacks/official" }
  let fixtures_dir = if args.length() >= 3 { args[2] } else { "tests/fixtures" }
  let errors = validate_pack(pack_dir, fixtures_dir)
  if errors.is_empty() {
    println("rules-validate: OK (\{pack_dir})")
    @env.exit(0)
  }
  for e in errors {
    println("rules-validate ERROR: \{e}")
  }
  @env.exit(2)
}
