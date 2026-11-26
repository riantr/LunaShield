// First-batch rule validation for MoonBit SAST.
//
// Reads rules_moonbit.json + rules_samples.json and, for every rule, runs the
// same match-and-predicate pipeline as libs/query-engine/engine.mbt against a
// positive and a negative fixture. A rule passes when positive hits equal
// expect_positive and negative hits equal expect_negative.
//
// Run from p0-spike/moonbit-grammar:
//   moon run --target native rules_check

#derive(@json.FromJson)
pub(all) struct Pred {
  kind : String
  capture : String
  value : String
}

#derive(@json.FromJson)
pub(all) struct Rule {
  id : String
  language : String
  severity : String
  cwe : Array[Int]
  owasp : Array[String]
  query : String
  predicates : Array[Pred]
  message : String
  enabled : Bool
}

#derive(@json.FromJson)
pub(all) struct Sample {
  rule_id : String
  positive : String
  negative : String
  expect_positive : Int
  expect_negative : Int
}

/// Evaluate one host-side predicate; mirrors engine.mbt eval_predicate exactly.
fn eval_pred(kind : String, text : String, value : String) -> Bool {
  match kind {
    "text_equals" => text == value
    "text_not_equals" => text != value
    "has_prefix" => text.has_prefix(value)
    "not_has_prefix" => !text.has_prefix(value)
    "has_suffix" => text.has_suffix(value)
    "not_has_suffix" => !text.has_suffix(value)
    "contains" => match text.find(value) {
      Some(_) => true
      None => false
    }
    "not_contains" => match text.find(value) {
      Some(_) => false
      None => true
    }
    _ => false
  }
}

/// Count hits for one rule against one source string.
/// Mirrors engine.mbt run_rules: compile query, walk matches, decode every
/// capture, require all predicates to pass. Returns (-1, "") on compile error.
fn count_hits(
  lang : @treesitter.Language,
  rule : Rule,
  src : String,
) -> (Int, String) raise {
  let parser = @treesitter.Parser::new()
  parser.set_language(lang)
  let source = @utf8.encode(src)
  let tree = match parser.parse(source) {
    Some(t) => t
    None => return (-1, "parse failed")
  }
  let query = @treesitter.Query::new(lang, rule.query) catch {
    e => return (-1, "compile line=\{e.row()} col=\{e.column()}: \{e.message()}")
  }
  let names = query.capture_names()
  let cursor = @treesitter.QueryCursor::new()
  let matches = cursor.matches(query, tree.root_node(), source)
  let mut hits = 0
  while matches.next() is Some(m) {
    let captures : Map[String, String] = Map([])
    for c in m.captures() {
      let idx = c.index.to_int()
      if idx >= 0 && idx < names.length() {
        let name = names[idx]
        let value = c.node.utf8_text(source) catch { _ => "" }
        captures.set(name, value)
      }
    }
    let mut ok = true
    for p in rule.predicates {
      match captures.get(p.capture) {
        None => { ok = false; break }
        Some(text) => if !eval_pred(p.kind, text, p.value) { ok = false; break }
      }
    }
    if ok { hits += 1 }
  }
  (hits, "")
}

async fn main raise {
  let lang = @pkg.language()
  let rules_text = @fs.read_file("rules_moonbit.json").text()
  let rules_json = @json.parse(rules_text)
  let rules : Array[Rule] = @json.from_json(rules_json)
  let samples_text = @fs.read_file("rules_samples.json").text()
  let samples_json = @json.parse(samples_text)
  let samples : Array[Sample] = @json.from_json(samples_json)
  let mut pass = 0
  let mut fail = 0
  for rule in rules {
    let mut sample : Sample? = None
    for s in samples {
      if s.rule_id == rule.id { sample = Some(s) }
    }
    let sample = match sample {
      Some(s) => s
      None => {
        println("FAIL " + rule.id + " NO SAMPLE")
        fail += 1
        continue
      }
    }
    if rule.language != "moonbit" || !rule.enabled {
      println("SKIP " + rule.id)
      continue
    }
    let (pos_hits, pos_err) = count_hits(lang, rule, sample.positive)
    let (neg_hits, neg_err) = count_hits(lang, rule, sample.negative)
    let ok = pos_hits == sample.expect_positive &&
      neg_hits == sample.expect_negative
    println((if ok { "PASS " } else { "FAIL " }) + rule.id +
      " pos=" + pos_hits.to_string() + "/" + sample.expect_positive.to_string() +
      " neg=" + neg_hits.to_string() + "/" + sample.expect_negative.to_string() +
      (if pos_err == "" && neg_err == "" { "" } else {
        " err[" + pos_err + "|" + neg_err + "]"
      }))
    if ok { pass += 1 } else { fail += 1 }
  }
  println("RULES TOTAL=" + (pass + fail).to_string() + " PASS=" + pass.to_string() +
    " FAIL=" + fail.to_string())
}
