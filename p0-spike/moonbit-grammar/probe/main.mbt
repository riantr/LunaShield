// Query probe for the MoonBit grammar binding.
//
// Verifies the assumptions that rule authoring depends on:
//   1. Queries without named-field anchors compile (this grammar has 0 fields).
//   2. Capture names, indices and texts are stable across repeated runs.
//   3. Positional anchors (`.`) select exactly one argument, and host-side
//      predicates can discriminate package/function names.
//   4. Four patterns needed by the first rule batch: interpolation taint,
//      second-argument anchoring, multiline-string secrets, empty catch.
//
// Run: moon build --target native probe && <exe>   (from this directory)

struct Probe {
  label : String
  src : String
  query : String
  expect_matches : Int
  expect_first : Array[String]
}

fn raw(lang : @treesitter.Language, src : String) -> (@treesitter.Tree, Bytes) raise {
  let parser = @treesitter.Parser::new()
  parser.set_language(lang)
  let source = @utf8.encode(src)
  match parser.parse(source) {
    Some(tree) => (tree, source)
    None => abort("parse failed")
  }
}

fn text(node : @treesitter.Node, source : Bytes) -> String {
  node.utf8_text(source) catch { _ => "" }
}

fn run(probe : Probe, lang : @treesitter.Language) -> Bool raise {
  let (tree, source) = raw(lang, probe.src)
  let query = @treesitter.Query::new(lang, probe.query) catch {
    e => {
      println("FAIL " + probe.label + " COMPILE line=" + e.row().to_string() +
        " col=" + e.column().to_string() + " msg=" + e.message())
      return false
    }
  }
  let names = query.capture_names()
  let mut rows : Array[String] = []
  for _ in 0..<2 {
    let cursor = @treesitter.QueryCursor::new()
    let matches = cursor.matches(query, tree.root_node(), source)
    let one : Array[String] = []
    while matches.next() is Some(m) {
      let mut row = ""
      let mut primary = 2147483647
      for c in m.captures() {
        let idx = c.index.to_int()
        let name = if idx >= 0 && idx < names.length() { names[idx] } else { "?" }
        if idx < primary { primary = idx }
        row = row + name + "=" + text(c.node, source) + ";"
      }
      one.push(row)
    }
    if rows.length() == 0 {
      rows = one
    } else if rows != one {
      println("FAIL " + probe.label + " UNSTABLE first=" + rows.join("|") +
        " second=" + one.join("|"))
      return false
    }
  }
  let expected = probe.expect_first.join("")
  let ok = rows.length() == probe.expect_matches &&
    (probe.expect_first.length() == 0 || rows[0].has_prefix(expected))
  println((if ok { "PASS " } else { "FAIL " }) + probe.label +
    " matches=" + rows.length().to_string() +
    " first=" + (if rows.length() > 0 { rows[0] } else { "<none>" }))
  ok
}

let call_src = "fn main {\n  let a = @fs.read_file(\"p1\")\n  let b = @fs.write_file(\"p2\", data)\n}\n"
let write_src = "fn main {\n  let path = \"out.txt\"\n  let data = @env.get_env_var(\"DATA\")\n  @fs.write_file(path, data)\n}\n"
let empty_catch_src = "fn main {\n  try { risky() } catch { }\n}\n"
let nonempty_catch_src = "fn main {\n  try { risky() } catch { e => println(e) }\n}\n"

let probes : Array[Probe] = [
  {
    label: "no_named_field_apply",
    src: call_src,
    query:
      "(apply_expression (qualified_identifier (package_identifier) @pkg (dot_lowercase_identifier) @fn) (arguments . (argument) @arg)) @call",
    expect_matches: 2,
    expect_first: ["call=@fs.read_file(\"p1\");", "pkg=@fs;", "fn=.read_file;", "arg=\"p1\";"],
  },
  {
    label: "positional_anchor_single_arg",
    src: call_src,
    query:
      "(apply_expression (qualified_identifier (package_identifier) @pkg (dot_lowercase_identifier) @fn) (arguments . (argument) @arg)) @call",
    expect_matches: 2,
    expect_first: [],
  },
  {
    label: "without_anchor_all_args",
    src: call_src,
    query:
      "(apply_expression (qualified_identifier (package_identifier) @pkg (dot_lowercase_identifier) @fn) (arguments (argument) @arg)) @call",
    expect_matches: 3,
    expect_first: [],
  },
  {
    label: "method_ctor",
    src: "fn main {\n  let p = @process.Process::new(\"ls\")\n}\n",
    query:
      "(apply_expression (method_expression (type_name (qualified_type_identifier (package_identifier) @pkg (dot_identifier (dot_uppercase_identifier) @ty))) (lowercase_identifier) @fn) (arguments . (argument) @arg)) @call",
    expect_matches: 1,
    expect_first: ["call=@process.Process::new(\"ls\");", "pkg=@process;", "ty=.Process;", "fn=new;", "arg=\"ls\";"],
  },
  {
    label: "const_secret",
    src: "const API_KEY : String = \"sk_live_1234567890\"\n",
    query:
      "(const_definition (uppercase_identifier) @name (type_annotation) (atomic_expression (literal (string_literal) @str))) @decl",
    expect_matches: 1,
    expect_first: ["decl=const API_KEY : String = \"sk_live_1234567890\";", "name=API_KEY;", "str=\"sk_live_1234567890\";"],
  },
  // --- four patterns needed by the first rule batch -----------------------
  {
    label: "string_interpolation_taint",
    src: "fn main {\n  let id = \"u1\"\n  println(\"id=\\{id}\")\n}\n",
    query:
      "(string_interpolation (interpolator (qualified_identifier (lowercase_identifier) @var))) @str",
    expect_matches: 1,
    expect_first: ["str=\"id=\\{id}\";", "var=id;"],
  },
  {
    label: "write_second_arg_anchor",
    src: write_src,
    query:
      "(apply_expression (qualified_identifier (package_identifier) @pkg (dot_lowercase_identifier) @fn) (arguments (argument) . (argument) @arg)) @call",
    expect_matches: 1,
    expect_first: ["call=@fs.write_file(path, data);", "pkg=@fs;", "fn=.write_file;", "arg=data;"],
  },
  {
    // Both anchor forms work: `(argument) . (argument)` and the documented
    // `(argument) _ . (argument)` each select exactly the second argument.
    label: "write_second_arg_wildcard_pattern",
    src: write_src,
    query:
      "(apply_expression (qualified_identifier (package_identifier) @pkg (dot_lowercase_identifier) @fn) (arguments (argument) _ . (argument) @arg)) @call",
    expect_matches: 1,
    expect_first: ["call=@fs.write_file(path, data);", "pkg=@fs;", "fn=.write_file;", "arg=data;"],
  },
  {
    label: "multiline_secret",
    src: "const KEY : String = #|sk_live_1234567890|#\n",
    query:
      "(const_definition (uppercase_identifier) @name (type_annotation) (atomic_expression (literal (multiline_string_literal (multiline_string_fragment (multiline_string_content) @secret))))) @decl",
    expect_matches: 1,
    // Grammar quirk: multiline_string_content greedily includes the closing
    // `|#`. Rules must prefix-match the secret, not compare the whole text.
    expect_first: ["decl=const KEY : String = #|sk_live_1234567890|#;", "name=KEY;", "secret=sk_live_1234567890|#;"],
  },
  {
    label: "empty_catch_matches",
    src: empty_catch_src,
    query: "((try_catch_clause) @catch (#not-match? @catch \"=>\"))",
    expect_matches: 1,
    expect_first: ["catch=catch { };"],
  },
  {
    label: "nonempty_catch_rejected",
    src: nonempty_catch_src,
    query: "((try_catch_clause) @catch (#not-match? @catch \"=>\"))",
    expect_matches: 0,
    expect_first: [],
  },
]

fn main raise {
  let lang = @pkg.language()
  let mut pass = 0
  let mut fail = 0
  for p in probes {
    if run(p, lang) { pass += 1 } else { fail += 1 }
  }
  println("PROBE TOTAL=" + (pass + fail).to_string() + " PASS=" + pass.to_string() +
    " FAIL=" + fail.to_string())
}
