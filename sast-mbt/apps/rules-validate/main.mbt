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
  // The taint manifest is optional, but a declared one must be checksummed
  // too: an unnoticed edit could silently disable a sink without touching
  // rules.json (and therefore without invalidating its checksum).
  match obj.get("taint_file") {
    Some(@json.String(tf)) => {
      let expected_taint = match obj.get("taint_sha256") {
        Some(@json.String(s)) => s
        _ => return "manifest.json: taint_file declared without taint_sha256"
      }
      let taint_path = "\{pack_dir}/\{tf}"
      guard @fs.exists(taint_path) else { return "missing \{taint_path}" }
      let taint_bytes = @utf8.encode(read_text(taint_path))
      let taint_actual = @bithash.hex_encode(@bithash.sha256_raw(taint_bytes))
      if taint_actual != expected_taint {
        return "\{tf} SHA-256 mismatch: expected \{expected_taint}, got \{taint_actual}"
      }
    }
    _ => ()
  }
  ""
}

///|
/// Manifest-declared path, with the conventional name as a fallback for packs
/// that predate the `taint_file` field.
async fn manifest_taint_path(pack_dir : String) -> String {
  let manifest_json = @json.parse(read_text("\{pack_dir}/manifest.json")) catch {
    _ => return "\{pack_dir}/taint.json"
  }
  match manifest_json {
    @json.Object(obj) =>
      match obj.get("taint_file") {
        Some(@json.String(s)) => "\{pack_dir}/\{s}"
        _ => "\{pack_dir}/taint.json"
      }
    _ => "\{pack_dir}/taint.json"
  }
}

///|
/// A sink declared under language L must point at a rule whose language is L.
/// `validate_spec` only checks that the id exists; this closes the second half
/// of the manifest contract without changing the frozen taint API.
fn check_taint_languages(
  spec : @taint.TaintSpec,
  rules : Array[@rule.Rule],
) -> Array[String] {
  let errors : Array[String] = []
  for lang in spec.languages {
    for sink in lang.sinks {
      for r in rules {
        if r.id == sink.rule_id && r.language != lang.language {
          errors.push(
            "taint.json: \{lang.language}: sink '\{sink.rule_id}' belongs to language '\{r.language}'",
          )
        }
      }
    }
  }
  errors
}

///|
/// Validate the optional taint manifest. A missing file is allowed (older
/// packs); a present one must parse, satisfy the taint schema, and agree with
/// the rule pack's id/language pairs.
async fn validate_taint(
  pack_dir : String,
  rules : Array[@rule.Rule],
) -> Array[String] {
  let errors : Array[String] = []
  let path = manifest_taint_path(pack_dir)
  guard @fs.exists(path) else { return errors }
  let json = @json.parse(read_text(path)) catch {
    e => {
      errors.push("taint.json parse error: \{e}")
      return errors
    }
  }
  let spec = @taint.parse_spec(json) catch {
    @taint.TaintSpecError(message~) => {
      errors.push("taint.json: \{message}")
      return errors
    }
  }
  @taint.validate_spec(spec, rules.map(fn(r) { r.id })) catch {
    // validate_spec messages already carry the "taint.json:" path prefix.
    @taint.TaintSpecError(message~) => errors.push(message)
  }
  for e in check_taint_languages(spec, rules) {
    errors.push(e)
  }
  errors
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
  for e in validate_taint(pack_dir, rules) {
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
