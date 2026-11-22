// T4 verification: content fingerprint (cache key) + gitignore matching.

///|
fn sha256_hex(s : String) -> String {
  @bithash.hex_encode(@bithash.sha256_raw(@utf8.encode(s)))
}

///|
fn core_hash_seed0(s : String) -> Int {
  let h = Hasher(seed=0)
  h.combine_string(s)
  h.finalize()
}

test "T4a: core Hasher(seed=0) is deterministic" {
  let h1 = core_hash_seed0("cache-key-content")
  let h2 = core_hash_seed0("cache-key-content")
  assert_true(h1 == h2)
  assert_true(h1 != core_hash_seed0("other-content"))
}

test "T4b: SHA-256 matches NIST vector for abc" {
  let got = sha256_hex("abc")
  assert_true(
    got == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  )
}

test "T4b2: SHA-256 incremental equals one-shot" {
  let st = @bithash.Sha256State::new()
  st.update_string("ab")
  st.update_string("c")
  let inc = @bithash.hex_encode(st.finish_raw())
  assert_true(inc == sha256_hex("abc"))
}

test "T4b3: SHA-256 differs on 1-byte change" {
  assert_true(sha256_hex("abc") != sha256_hex("abd"))
}

test "T4c: gitignore basic patterns" {
  let m = @bitignore.Matcher::new()
  m.add_rules("", "*.log\nbuild/\n")
  assert_true(m.is_ignored("app.log", false))
  assert_true(!m.is_ignored("app.txt", false))
  assert_true(m.is_ignored("build/out.js", false))
  assert_true(m.is_ignored("build", true))
}

test "T4c2: gitignore negation" {
  let m = @bitignore.Matcher::new()
  m.add_rules("", "*.log\n!important.log\n")
  assert_true(m.is_ignored("debug.log", false))
  assert_true(!m.is_ignored("important.log", false))
}

test "T4c3: gitignore anchored vs unanchored" {
  let m = @bitignore.Matcher::new()
  m.add_rules("", "/root-only.txt\nsub.txt\n")
  assert_true(m.is_ignored("root-only.txt", false))
  assert_true(!m.is_ignored("src/root-only.txt", false))
  assert_true(m.is_ignored("src/sub.txt", false))
}

test "T4c4: gitignore nested base + truncate" {
  let m = @bitignore.Matcher::new()
  m.add_rules("", "*.tmp\n")
  m.add_rules("src", "*.gen.js\n")
  assert_true(m.is_ignored("a.tmp", false))
  assert_true(m.is_ignored("src/a.gen.js", false))
  assert_true(!m.is_ignored("a.gen.js", false))
  let n = m.len()
  m.truncate(n - 1)
  assert_true(!m.is_ignored("src/a.gen.js", false))
}
