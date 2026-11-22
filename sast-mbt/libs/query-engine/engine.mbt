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
    let query = @treesitter.Query::new(language, rule.query) catch {
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
      let captures : Map[String, String] = Map([])
      let mut primary : @treesitter.Node? = None
      let mut primary_index : Int32 = 2147483647
      for c in m.captures() {
        let idx = c.index
        if idx >= 0 && idx.to_int() < names.length() {
          let name = names[idx.to_int()]
          captures.set(name, @parser.text_of_node(c.node, parsed.source))
          if idx < primary_index {
            primary_index = idx
            primary = Some(c.node)
          }
        }
      }
      match primary {
        None => ()
        Some(node) =>
          if eval_predicates(rule.predicates, captures) {
            hits.push({
              rule_id: rule.id,
              severity: rule.severity,
              cwe: rule.cwe,
              owasp: rule.owasp,
              message: rule.message,
              primary: @parser.loc_of_node(parsed.path, node),
              snippet: @parser.text_of_node(node, parsed.source),
              captures,
            })
          }
      }
    }
  }
  { hits, failures, }
}
