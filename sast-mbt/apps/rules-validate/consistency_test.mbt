///|
/// The rule schema (`libs/rule`) keeps its own language list so it stays free of
/// grammar dependencies. This test is the guard against the two lists drifting.
test "rule language list matches lang-registry exactly" {
  let rule_langs = @rule.registered_languages()
  let registry_langs = @lang.language_ids()
  assert_eq(rule_langs.length(), registry_langs.length())
  for id in registry_langs {
    assert_true(rule_langs.contains(id))
  }
  for id in rule_langs {
    assert_true(registry_langs.contains(id))
  }
}

///|
test "every registry language resolves to a primary fixture extension" {
  for id in @lang.language_ids() {
    assert_true(@lang.spec_by_id(id).unwrap().extensions.length() > 0)
  }
}
