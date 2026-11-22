test "all grammar language() load" {
  let langs : Array[@treesitter.Language] = [
    @js.language(),
    @ts.language_tsx(),
    @ts.language_typescript(),
    @py.language(),
    @java.language(),
    @json.language(),
  ]
  assert_true(langs.length() == 6)
}
