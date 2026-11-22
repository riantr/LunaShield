// P0-1 end-to-end: read JS file -> parse AST -> run Query -> emit JSON Finding.
// Usage: p0-e2e <file.js>

#derive(@json.ToJson)
struct Finding {
  rule_id : String
  severity : String
  line : Int
  column : Int
  snippet : String
  fingerprint : String
}

#derive(@json.ToJson)
struct Report {
  file : String
  finding_count : Int
  findings : Array[Finding]
}

///|
fn fingerprint_of(rule_id : String, snippet : String) -> String {
  let input = @utf8.encode(rule_id + "|" + snippet)
  @bithash.hex_encode(@bithash.sha256_raw(input))
}

///|
fn scan_source(source_text : String) -> Array[Finding] {
  let language = @js.language()
  // Rule JS001: any call whose callee identifier is `eval`.
  let query = @treesitter.Query::new(
    language,
    "(call_expression function: (identifier) @callee (#eq? @callee \"eval\"))",
  ) catch {
    e => abort("query compile failed: \{e}")
  }
  let parser = @treesitter.Parser::new()
  parser.set_language(language) catch {
    e => abort("set_language failed: \{e}")
  }
  let source = @utf8.encode(source_text)
  guard parser.parse(source) is Some(tree) else { abort("parse failed") }

  let cursor = @treesitter.QueryCursor::new()
  let matches = cursor.matches(query, tree.root_node(), source)
  let findings : Array[Finding] = []
  while matches.next() is Some(m) {
    for capture in m.captures() {
      let node = capture.node
      let pos = node.start_position()
      let snippet = node.utf8_text(source) catch { _ => "" }
      findings.push(Finding::{
        rule_id: "JS001",
        severity: "HIGH",
        line: pos.row.to_int() + 1,
        column: pos.column.to_int() + 1,
        snippet,
        fingerprint: fingerprint_of("JS001", snippet),
      })
    }
  }
  findings
}

///|
async fn main {
  let args = @env.args()
  guard args.length() >= 2 else {
    println("usage: p0-e2e <file.js>")
    abort("missing file argument")
  }
  let path = args[1]
  let source_text = @fs.read_file(path).text()
  let findings = scan_source(source_text)
  let report = Report::{ file: path, finding_count: findings.length(), findings }
  println(@json.to_json(report).stringify())
}
