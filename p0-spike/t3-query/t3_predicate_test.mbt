///|
fn count_matches(query_src : String, json_src : String) -> Int {
  let language = @tree_sitter_json.language()
  let query = @treesitter.Query::new(language, query_src) catch {
    e => abort("query compile failed: \{e}")
  }
  let parser = @treesitter.Parser::new()
  parser.set_language(language) catch { e => abort("set_language failed: \{e}") }
  let source = @utf8.encode(json_src)
  guard parser.parse(source) is Some(tree) else { abort("parse failed") }
  let cursor = @treesitter.QueryCursor::new()
  let matches = cursor.matches(query, tree.root_node(), source)
  let mut count = 0
  while matches.next() is Some(_) {
    count += 1
  }
  count
}

///|
test "T3a: plain query without predicate matches both values" {
  let json = "{\"kind\": \"danger\", \"safe\": \"ok\"}"
  // pair 节点任意 value 都命中，期望 2
  let n = count_matches("(pair value: (_) @v)", json)
  inspect(n, content="2")
}

///|
test "T3b: #eq? predicate filters by captured text" {
  let json = "{\"kind\": \"danger\", \"safe\": \"ok\"}"
  // 只有 kind 的 value 文本为 "danger" 才命中，期望 1
  let n = count_matches(
    "(pair key: (string) @k value: (string) @v (#eq? @v \"\\\"danger\\\"\"))",
    json,
  )
  inspect(n, content="1")
}

///|
test "T3c: #match? regex predicate filters by captured text" {
  let json = "{\"kind\": \"danger\", \"safe\": \"ok\"}"
  // 正则匹配 danger，期望 1
  let n = count_matches(
    "(pair key: (string) @k value: (string) @v (#match? @v \"danger\"))",
    json,
  )
  inspect(n, content="1")
}

///|
test "T3d: #any-of? predicate filters by captured text" {
  let json = "{\"a\": \"x\", \"b\": \"y\"}"
  let n = count_matches(
    "(pair value: (string) @v (#any-of? @v \"\\\"x\\\"\" \"\\\"z\\\"\"))",
    json,
  )
  inspect(n, content="1")
}
