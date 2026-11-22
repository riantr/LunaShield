// Manifest loading, validation and lookup. Validation is strict on purpose: a
// typo in a sink's rule id would silently disable taint for that rule, which is
// exactly the class of bug rules-validate exists to prevent.

///|
pub suberror TaintSpecError {
  TaintSpecError(message~ : String)
}

///|
/// Parse `taint.json` content.
pub fn parse_spec(value : @json.Json) -> TaintSpec raise TaintSpecError {
  @json.from_json(value) catch {
    e => raise TaintSpecError(message="taint spec is not valid: \{e}")
  }
}

///|
/// Language block for `language`, if configured.
pub fn for_language(spec : TaintSpec, language : String) -> LanguageTaint? {
  for l in spec.languages {
    if l.language == language {
      return Some(l)
    }
  }
  None
}

///|
/// Sink declaration for a rule id inside one language block.
pub fn sink_for(lang : LanguageTaint, rule_id : String) -> SinkRule? {
  for s in lang.sinks {
    if s.rule_id == rule_id {
      return Some(s)
    }
  }
  None
}

///|
/// Languages covered by the manifest, in declaration order.
pub fn supported_languages(spec : TaintSpec) -> Array[String] {
  spec.languages.map(fn(l) { l.language })
}

///|
fn contains_string(items : Array[String], value : String) -> Bool {
  for i in items {
    if i == value {
      return true
    }
  }
  false
}

///|
/// Structural validation.
///
/// `rule_ids` is the set of rule ids in the same pack: a sink pointing at a
/// non-existent rule is an error, because taint would never run for it.
pub fn validate_spec(
  spec : TaintSpec,
  rule_ids : Array[String],
) -> Unit raise TaintSpecError {
  guard spec.version.length() > 0 else {
    raise TaintSpecError(message="taint.json: 'version' must not be empty")
  }
  guard spec.languages.length() > 0 else {
    raise TaintSpecError(message="taint.json: 'languages' must not be empty")
  }
  let seen_languages : Array[String] = []
  for lang in spec.languages {
    let label = if lang.language.length() == 0 {
      "<unnamed>"
    } else {
      lang.language
    }
    guard lang.language.length() > 0 else {
      raise TaintSpecError(
        message="taint.json: language entry without 'language'",
      )
    }
    guard !contains_string(seen_languages, lang.language) else {
      raise TaintSpecError(message="taint.json: duplicate language '\{label}'")
    }
    seen_languages.push(lang.language)
    let seen_sources : Array[String] = []
    for s in lang.sources {
      guard s.name.length() > 0 else {
        raise TaintSpecError(
          message="taint.json: \{label}: source without 'name'",
        )
      }
      guard s.node_kind.length() > 0 else {
        raise TaintSpecError(
          message="taint.json: \{label}: source '\{s.name}' without 'node_kind'",
        )
      }
      guard !contains_string(seen_sources, s.name) else {
        raise TaintSpecError(
          message="taint.json: \{label}: duplicate source name '\{s.name}'",
        )
      }
      seen_sources.push(s.name)
    }
    let seen_sanitizers : Array[String] = []
    for t in lang.sanitizers {
      guard t.name.length() > 0 else {
        raise TaintSpecError(
          message="taint.json: \{label}: sanitizer without 'name'",
        )
      }
      guard t.callee_contains.length() > 0 else {
        raise TaintSpecError(
          message="taint.json: \{label}: sanitizer '\{t.name}' without 'callee_contains'",
        )
      }
      guard !contains_string(seen_sanitizers, t.name) else {
        raise TaintSpecError(
          message="taint.json: \{label}: duplicate sanitizer name '\{t.name}'",
        )
      }
      seen_sanitizers.push(t.name)
    }
    let seen_sinks : Array[String] = []
    for k in lang.sinks {
      guard k.rule_id.length() > 0 else {
        raise TaintSpecError(
          message="taint.json: \{label}: sink without 'rule_id'",
        )
      }
      guard contains_string(rule_ids, k.rule_id) else {
        raise TaintSpecError(
          message="taint.json: \{label}: sink references unknown rule '\{k.rule_id}'",
        )
      }
      guard !contains_string(seen_sinks, k.rule_id) else {
        raise TaintSpecError(
          message="taint.json: \{label}: duplicate sink for rule '\{k.rule_id}'",
        )
      }
      seen_sinks.push(k.rule_id)
    }
  }
}
