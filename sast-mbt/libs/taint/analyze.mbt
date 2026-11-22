// P2-S4b-2: intra-function taint confirmation.
//
// This is a deliberately small, explainable v0: given a rule hit that the
// manifest declares as a sink, look for a user-controlled source *inside the
// same function*, in source order before the sink, whose value (by variable
// name) reaches the sink argument, and check whether a sanitizer sits between
// them. It is an approximation, not dataflow: no CFG, no path sensitivity, no
// inter-procedural reasoning (see P2_污点接口设计.md §1).
//
// The most important invariant is unchanged from S4a: a rule that is not a
// sink, a missing tree, or a language block without sources always yields
// `NotApplicable`, so an unfinished or partially configured analysis can never
// prune a finding by accident.

///|
fn contains_substring(text : String, needle : String) -> Bool {
  match text.find(needle) {
    Some(_) => true
    None => false
  }
}

///|
fn is_ident_char(c : Char) -> Bool {
  ('a' <= c && c <= 'z') ||
  ('A' <= c && c <= 'Z') ||
  ('0' <= c && c <= '9') ||
  c == '_' ||
  c == '$'
}

///|
/// Extract ASCII identifier tokens in source order, deduplicated.
/// Used for the "same variable name" approximation: a source bound to `x`
/// reaches a sink argument that mentions `x`.
fn identifiers(text : String) -> Array[String] {
  let out : Array[String] = []
  let mut acc = ""
  let mut active = false
  for c in text {
    if is_ident_char(c) {
      acc = acc + "\{c}"
      active = true
    } else if active {
      out.push(acc)
      acc = ""
      active = false
    }
  }
  if active {
    out.push(acc)
  }
  let uniq : Array[String] = []
  for token in out {
    if !uniq.contains(token) {
      uniq.push(token)
    }
  }
  uniq
}

///|
fn simple_identifier(text : String) -> Bool {
  let tokens = identifiers(text)
  tokens.length() == 1 && tokens[0] == text
}

///|
fn intersects(a : Array[String], b : Array[String]) -> Bool {
  for x in a {
    for y in b {
      if x == y {
        return true
      }
    }
  }
  false
}

///|
fn is_function_kind(kind : String) -> Bool {
  contains_substring(kind, "function") ||
  contains_substring(kind, "method") ||
  kind == "arrow_function" ||
  kind == "lambda_expression" ||
  kind == "constructor_declaration"
}

///|
fn is_call_kind(kind : String) -> Bool {
  contains_substring(kind, "call") ||
  kind == "method_invocation" ||
  kind == "object_creation_expression" ||
  kind == "new_expression"
}

///|
/// The call/assignment statement that owns the primary capture. `primary` is
/// usually the callee identifier (smallest capture index), so walking up to the
/// enclosing call gives us a byte range that also covers inline sources such
/// as `eval(req.query.x)`.
fn sink_statement(node : @treesitter.Node) -> @treesitter.Node {
  let kind = node.kind()
  if is_call_kind(kind) || contains_substring(kind, "assignment") {
    node
  } else {
    match node.parent() {
      Some(parent) => sink_statement(parent)
      None => node
    }
  }
}

///|
/// Nearest enclosing function (or the root when the sink is at top level).
fn enclosing_function(node : @treesitter.Node) -> @treesitter.Node {
  if is_function_kind(node.kind()) {
    node
  } else {
    match node.parent() {
      Some(parent) => enclosing_function(parent)
      None => node
    }
  }
}

///|
/// Variable a source expression is bound to, if the declaration/assignment is
/// visible in the tree. Falls back to the first identifier inside the source
/// text (`req.query.x` -> `req`) so that inline sources such as
/// `eval(req.query.x)` can still be matched against the sink argument.
fn bound_variable(node : @treesitter.Node, source : Bytes) -> String {
  let text = @parser.text_of_node(node, source)
  let mut cur = node.parent()
  let mut depth = 0
  while depth < 4 {
    match cur {
      None => break
      Some(ancestor) => {
        let kind = ancestor.kind()
        if contains_substring(kind, "declarator") ||
          contains_substring(kind, "assignment") {
          for field in ["name", "left"] {
            match ancestor.child_by_field_name(field) {
              Some(target) => {
                let name = @parser.text_of_node(target, source)
                if simple_identifier(name) {
                  return name
                }
              }
              None => ()
            }
          }
          return ""
        }
        cur = ancestor.parent()
        depth += 1
      }
    }
  }
  let tokens = identifiers(text)
  if tokens.length() > 0 {
    tokens[0]
  } else {
    ""
  }
}

///|
/// One source occurrence found inside the enclosing function.
priv struct SourceEvent {
  loc : @core.SourceLoc
  start : Int32
  end : Int32
  name : String
  bound : String
  tokens : Array[String]
}

///|
/// One sanitizer call found inside the enclosing function.
priv struct SanitizerEvent {
  loc : @core.SourceLoc
  start : Int32
  end : Int32
  name : String
  tokens : Array[String]
}

///|
/// Walk the function subtree in source order (pre-order DFS) and collect the
/// events that matter for the approximation.
fn collect_events(
  node : @treesitter.Node,
  lang : LanguageTaint,
  parsed : @parser.ParsedFile,
  sources : Array[SourceEvent],
  sanitizers : Array[SanitizerEvent],
) -> Unit {
  let text = @parser.text_of_node(node, parsed.source)
  let kind = node.kind()
  for rule in lang.sources {
    if kind == rule.node_kind &&
      (
        rule.text_contains.length() == 0 ||
        contains_substring(text, rule.text_contains)
      ) {
      sources.push({
        loc: @parser.loc_of_node(parsed.path, node),
        start: node.start_byte(),
        end: node.end_byte(),
        name: rule.name,
        bound: bound_variable(node, parsed.source),
        tokens: identifiers(text),
      })
      break
    }
  }
  if is_call_kind(kind) {
    for rule in lang.sanitizers {
      if contains_substring(text, rule.callee_contains) {
        sanitizers.push({
          loc: @parser.loc_of_node(parsed.path, node),
          start: node.start_byte(),
          end: node.end_byte(),
          name: rule.name,
          tokens: identifiers(text),
        })
        break
      }
    }
  }
  let count = node.child_count()
  let mut i = 0
  while i < count {
    match node.child(i) {
      Some(child) => collect_events(child, lang, parsed, sources, sanitizers)
      None => ()
    }
    i += 1
  }
}

///|
/// Confirm (or refute) one hit using the taint manifest of its language.
///
/// - `NotApplicable` -> no language block, no tree, or rule is not a sink.
/// - `Confirmed`     -> source reaches the sink argument un-sanitized.
/// - `Sanitized`     -> a sanitizer sits between the reaching source and sink.
/// - `NoSource`      -> no source reaches the sink argument in this function.
pub fn analyze(
  parsed : @parser.ParsedFile,
  hit : @core.RawHit,
  lang : LanguageTaint,
) -> TaintResult {
  let sink = match sink_for(lang, hit.rule_id) {
    None =>
      return no_opinion(
        "rule '\{hit.rule_id}' is not a taint sink for '\{lang.language}'",
      )
    Some(found) => found
  }
  let tree = match parsed.tree {
    None => return no_opinion("no syntax tree available for taint analysis")
    Some(found) => found
  }
  let sink_node = match
    tree
    .root_node()
    .descendant_for_byte_range(
      hit.primary.byte_offset,
      hit.primary.byte_offset + 1,
    ) {
    None => return no_opinion("sink node not found in syntax tree")
    Some(found) => found
  }
  let scope = enclosing_function(sink_node)
  let sources : Array[SourceEvent] = []
  let sanitizers : Array[SanitizerEvent] = []
  collect_events(scope, lang, parsed, sources, sanitizers)

  let sink_arg = if sink.capture.length() == 0 {
    hit.snippet
  } else {
    match hit.captures.get(sink.capture) {
      Some(value) => value
      None => hit.snippet
    }
  }
  let sink_tokens = identifiers(sink_arg)
  let sink_end = sink_statement(sink_node).end_byte()

  // A source reaches the sink when it sits inside the same function before the
  // end of the sink statement (inline sources are nested in the sink argument,
  // so their start byte is still below `sink_end`) and its names intersect the
  // sink argument's identifiers (the "same variable name" approximation).
  let reaching : Array[SourceEvent] = []
  for source in sources {
    if source.start >= sink_end {
      continue
    }
    let names : Array[String] = []
    if source.bound.length() > 0 {
      names.push(source.bound)
    }
    for token in source.tokens {
      names.push(token)
    }
    if intersects(names, sink_tokens) {
      reaching.push(source)
    }
  }

  if reaching.length() == 0 {
    return {
      verdict: NoSource,
      source: None,
      sanitizer: None,
      detail: "no taint source reaches '\{sink_arg}' for rule '\{hit.rule_id}'",
    }
  }

  // A sanitizer neutralizes a reaching source when it mentions the same name
  // and either wraps the source (`escapeHtml(req.query.x)`) or appears after
  // it but before the sink (`const x = src; eval(escapeHtml(x))`). Both are
  // source-order facts, so they fit the v0 approximation.
  let first = reaching[0]
  let names : Array[String] = []
  if first.bound.length() > 0 {
    names.push(first.bound)
  }
  for token in first.tokens {
    names.push(token)
  }
  for san in sanitizers {
    let wraps = san.start <= first.start && san.end >= first.end
    let follows = san.start >= first.end && san.end <= sink_end
    if (wraps || follows) && intersects(san.tokens, names) {
      return {
        verdict: Sanitized,
        source: Some(first.loc),
        sanitizer: Some(san.loc),
        detail: "sanitizer '\{san.name}' neutralizes source '\{first.name}' before rule '\{hit.rule_id}'",
      }
    }
  }

  {
    verdict: Confirmed,
    source: Some(first.loc),
    sanitizer: None,
    detail: "source '\{first.name}' reaches '\{sink_arg}' for rule '\{hit.rule_id}'",
  }
}

///|
/// Convenience wrapper used by the orchestrator: resolve the language block first,
/// and treat "language not configured" as no opinion.
pub fn analyze_with_spec(
  parsed : @parser.ParsedFile,
  hit : @core.RawHit,
  spec : TaintSpec,
) -> TaintResult {
  match for_language(spec, parsed.language) {
    None =>
      no_opinion("no taint configuration for language '\{parsed.language}'")
    Some(lang) => analyze(parsed, hit, lang)
  }
}
