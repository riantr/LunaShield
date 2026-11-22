///|
test "registry: six languages in registration order" {
  assert_eq(@lang-registry.language_ids(), [
    "javascript", "typescript", "tsx", "python", "java", "json",
  ])
}

///|
test "registry: extension mapping covers every documented extension" {
  let cases : Array[(String, String)] = [
    ("js", "javascript"),
    ("jsx", "javascript"),
    ("mjs", "javascript"),
    ("cjs", "javascript"),
    ("ts", "typescript"),
    ("tsx", "tsx"),
    ("py", "python"),
    ("java", "java"),
    ("json", "json"),
  ]
  for pair in cases {
    let (ext, want) = pair
    let got = match @lang-registry.spec_by_extension(ext) {
      Some(s) => s.id
      None => "<none>"
    }
    assert_eq(got, want)
  }
}

///|
test "registry: extension normalization accepts dot and uppercase" {
  assert_eq(@lang-registry.extension_of("src/App.TSX"), Some("tsx"))
  assert_eq(@lang-registry.normalize_extension(".TS"), "ts")
  assert_eq(@lang-registry.spec_by_extension(".PY").unwrap().id, "python")
  assert_eq(@lang-registry.spec_by_path("a/b/c.ts").unwrap().id, "typescript")
}

///|
test "registry: dotfiles and extensionless paths do not resolve" {
  assert_eq(@lang-registry.extension_of(".gitignore"), None)
  assert_eq(@lang-registry.extension_of("Makefile"), None)
  assert_eq(@lang-registry.extension_of("src/.env"), None)
  assert_true(@lang-registry.spec_by_path("README") is None)
}

///|
test "registry: TSID/TSX use distinct grammar entry points" {
  let ts = @lang-registry.spec_by_id("typescript").unwrap().language()
  let tsx = @lang-registry.spec_by_id("tsx").unwrap().language()
  // Both grammars must load, and they must be genuinely different builds:
  // jsx_element only exists in the tsx grammar.
  assert_eq(ts.name(), Some("typescript"))
  assert_eq(tsx.name(), Some("tsx"))
  assert_true(ts.field_count() != tsx.field_count())
  assert_eq(ts.id_for_node_kind("jsx_element", true), 0)
  assert_true(tsx.id_for_node_kind("jsx_element", true) > 0)
}

///|
test "registry: every registration can be installed into a parser" {
  for s in @lang-registry.all_language_specs() {
    let parser = @treesitter.Parser::new()
    let installed = try {
      parser.set_language(s.language())
      true
    } catch {
      _ => false
    }
    assert_true(installed)
  }
}
