///|
let js_spec : @lang.LanguageSpec = @lang.spec_by_id("javascript").unwrap()

///|
test "parser: valid JavaScript yields a tree and no warnings" {
  let src = "function add(a, b) { return a + b; }\nadd(1, 2);\n"
  let parsed = @parser.parse(js_spec, src, "src/add.js")
  assert_true(parsed.tree is Some(_))
  assert_eq(parsed.warnings.length(), 0)
  assert_eq(parsed.language, "javascript")
  match parsed.tree {
    Some(tree) => assert_eq(tree.root_node().kind(), "program")
    None => abort("expected a tree")
  }
}

///|
test "parser: truncated JavaScript reports warnings but still returns a tree" {
  let src = "function broken(a) {\n  eval(a);\n"
  let parsed = @parser.parse(js_spec, src, "src/broken.js")
  // Tolerance requirement: the scan must continue with a usable tree.
  assert_true(parsed.tree is Some(_))
  assert_true(parsed.warnings.length() > 0)
  let first = parsed.warnings[0]
  assert_eq(first.path, "src/broken.js")
  assert_true(first.line >= 1)
  assert_true(first.column >= 1)
  assert_true(first.message.length() > 0)
}

///|
test "parser: garbage input stays bounded by the warning cap" {
  let src = "}{ ) ( ;;; ]]] ]]] ]]] ]]] ]]] ]]] ]]] ]]] ]]] ]]] ]]] ]]] ]]] ]]] ]]]"
  let parsed = @parser.parse(js_spec, src, "src/garbage.js")
  assert_true(parsed.tree is Some(_))
  assert_true(parsed.warnings.length() <= 20)
}

///|
test "parser: every registered grammar parses a minimal program" {
  let samples : Array[(String, String)] = [
    ("javascript", "const a = 1;\n"),
    ("typescript", "const a: number = 1;\n"),
    ("tsx", "const a = <div />;\n"),
    ("python", "a = 1\n"),
    ("java", "class A {}\n"),
    ("json", "{\"a\": 1}\n"),
  ]
  for pair in samples {
    let (id, src) = pair
    let spec = @lang.spec_by_id(id).unwrap()
    let parsed = @parser.parse(spec, src, "sample")
    assert_true(parsed.tree is Some(_))
    assert_eq(parsed.warnings.length(), 0)
  }
}

///|
test "parser: tsx grammar accepts JSX while typescript grammar rejects it" {
  let src = "const el = <div className=\"x\" />;\n"
  let tsx = @parser.parse(@lang.spec_by_id("tsx").unwrap(), src, "a.tsx")
  let ts = @parser.parse(@lang.spec_by_id("typescript").unwrap(), src, "a.ts")
  assert_eq(tsx.warnings.length(), 0)
  assert_true(ts.warnings.length() > 0)
}

///|
test "parser: node location and text helpers are 1-based" {
  let src = "eval(userInput);\n"
  let parsed = @parser.parse(js_spec, src, "src/eval.js")
  match parsed.tree {
    None => abort("expected a tree")
    Some(tree) => {
      let root = tree.root_node()
      let loc = @parser.loc_of_node("src/eval.js", root)
      assert_eq(loc.path, "src/eval.js")
      assert_eq(loc.line, 1)
      assert_eq(loc.column, 1)
      assert_eq(loc.byte_offset, 0)
      assert_eq(@parser.kind_of_node(root), "program")
      let child = root.named_child(0).unwrap()
      assert_eq(@parser.kind_of_node(child), "expression_statement")
      assert_eq(@parser.text_of_node(child, parsed.source), "eval(userInput);")
    }
  }
}
