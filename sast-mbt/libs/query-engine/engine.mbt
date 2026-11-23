// Query execution: compile one Query per rule, walk matches, evaluate the fixed
// host-side predicate set, and emit RawHits. Grammar failures never abort a scan.

///|
/// A rule that could not run (query failed to compile). Reported per file so the
/// CLI can surface it without aborting the scan.
#derive(Debug, Eq)
pub(all) struct RuleFailure {
  rule_id : String
  message : String
}

///|
/// Output of running every applicable rule against one parsed file.
pub struct RunResult {
  hits : Array[@core.RawHit]
  failures : Array[RuleFailure]
}

///|
fn contains_substring(text : String, needle : String) -> Bool {
  match text.find(needle) {
    Some(_) => true
    None => false
  }
}

///|
/// Evaluate one host-side predicate against a captured node's source text.
pub fn eval_predicate(p : @rule.PredicateSpec, text : String) -> Bool {
  match p.kind {
    @rule.TextEquals => text == p.value
    @rule.TextNotEquals => text != p.value
    @rule.HasPrefix => text.has_prefix(p.value)
    @rule.NotHasPrefix => !text.has_prefix(p.value)
    @rule.HasSuffix => text.has_suffix(p.value)
    @rule.NotHasSuffix => !text.has_suffix(p.value)
    @rule.Contains => contains_substring(text, p.value)
    @rule.NotContains => !contains_substring(text, p.value)
  }
}

///|
/// All predicates must pass. A predicate whose capture is absent from the match
/// fails closed (no finding): rules-validate guarantees the capture exists in the
/// query, so a miss here means this particular match did not bind it.
pub fn eval_predicates(
  preds : Array[@rule.PredicateSpec],
  captures : Map[String, String],
) -> Bool {
  for p in preds {
    let text = match captures.get(p.capture) {
      Some(t) => t
      None => return false
    }
    if !eval_predicate(p, text) {
      return false
    }
  }
  true
}

///|
/// Evaluate predicates against capture *nodes*, decoding a capture's text only
/// when a predicate actually references it.
///
/// Semantics are identical to `eval_predicates` (all must pass, a missing
/// capture fails closed); the difference is cost, since most matches are
/// rejected by one predicate and never need the other captures' text.
fn predicates_hold(
  preds : Array[@rule.PredicateSpec],
  bindings : Array[(@treesitter.Node, String)],
  source : Bytes,
) -> Bool {
  for p in preds {
    let mut found : String? = None
    for pair in bindings {
      let (n, name) = pair
      if name == p.capture {
        found = Some(@parser.text_of_node(n, source))
        break
      }
    }
    match found {
      None => return false
      Some(text) => if !eval_predicate(p, text) { return false }
    }
  }
  true
}

///|
/// Process-wide Query cache.
///
/// Compiling a tree-sitter query costs milliseconds while matching it on a
/// small file costs microseconds, and one scan re-compiles every rule once per
/// file. The rule set and grammar build are fixed for the whole scan, so the
/// compiled query can be shared across files. The key includes the grammar
/// identity (name + node/field counts), never the grammar alone, so a cache hit
/// can only ever reuse a query compiled against exactly the same grammar.
let query_cache : Map[String, @treesitter.Query] = Map([])

///|
fn query_cache_key(
  language : @treesitter.Language,
  query_text : String,
) -> String {
  let name = match language.name() {
    Some(n) => n
    None => "?"
  }
  name +
  "\u{0}" +
  language.field_count().to_string() +
  "\u{0}" +
  language.node_kind_count().to_string() +
  "\u{0}" +
  query_text
}

///|
fn query_for(
  language : @treesitter.Language,
  query_text : String,
) -> @treesitter.Query raise @treesitter.QueryError {
  let key = query_cache_key(language, query_text)
  match query_cache.get(key) {
    Some(q) => q
    None => {
      let q = @treesitter.Query::new(language, query_text)
      query_cache.set(key, q)
      q
    }
  }
}

///|
/// Run every enabled rule whose language matches `parsed` against `parsed`'s tree.
///
/// The grammar is taken from `tree.language()` so a rule's Query is always
/// compiled against exactly the grammar that produced the tree.
pub fn run_rules(
  parsed : @parser.ParsedFile,
  rules : Array[@rule.Rule],
) -> RunResult {
  let hits : Array[@core.RawHit] = []
  let failures : Array[RuleFailure] = []
  let tree = match parsed.tree {
    Some(t) => t
    None => return { hits, failures, }
  }
  let root = tree.root_node()
  let language = tree.language()
  for rule in rules {
    if !rule.enabled || rule.language != parsed.language {
      continue
    }
    let query = query_for(language, rule.query) catch {
      @treesitter.QueryError(row~, column~, message~, ..) => {
        failures.push({
          rule_id: rule.id,
          message: "query failed to compile at line \{row}, column \{column}: \{message}",
        })
        continue
      }
    }
    let names = query.capture_names()
    let cursor = @treesitter.QueryCursor::new()
    let matches = cursor.matches(query, root, parsed.source)
    while matches.next() is Some(m) {
      // Collect nodes first, decode text only when a predicate (or the hit
      // itself) asks for it: most matches die on a predicate, and decoding
      // every capture's text just to discard the match dominates matching time
      // for broad patterns.
      let bindings : Array[(@treesitter.Node, String)] = []
      let mut primary : @treesitter.Node? = None
      let mut primary_index : Int32 = 2147483647
      for c in m.captures() {
        let idx = c.index
        if idx >= 0 && idx.to_int() < names.length() {
          let name = names[idx.to_int()]
          bindings.push((c.node, name))
          if idx < primary_index {
            primary_index = idx
            primary = Some(c.node)
          }
        }
      }
      match primary {
        None => ()
        Some(node) =>
          if predicates_hold(rule.predicates, bindings, parsed.source) {
            let captures : Map[String, String] = Map([])
            for pair in bindings {
              let (n, name) = pair
              captures.set(name, @parser.text_of_node(n, parsed.source))
            }
            hits.push({
              rule_id: rule.id,
              language: parsed.language,
              severity: rule.severity,
              cwe: rule.cwe,
              owasp: rule.owasp,
              message: rule.message,
              primary: @parser.loc_of_node(parsed.path, node),
              snippet: @parser.text_of_node(node, parsed.source),
              captures,
              taint: @core.NotApplicable,
            })
          }
      }
    }
  }
  { hits, failures, }
}
