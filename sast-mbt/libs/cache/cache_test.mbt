///|
fn sample_finding() -> @core.Finding {
  {
    rule_id: "JS001",
    severity: @core.High,
    confidence: @core.High,
    cwe: [95],
    owasp: ["A03:2021"],
    primary: { path: "src/a.js", line: 2, column: 1, byte_offset: 13, },
    related: [],
    message: "Dynamic code execution via eval()",
    snippet: "eval",
    fingerprint: "cad6a9d4",
  }
}

///|
test "key: stable and sensitive to every input" {
  let base = @cache.entry_key("a.js", "h1", "r1", "0.1.0")
  assert_eq(@cache.entry_key("a.js", "h1", "r1", "0.1.0"), base)
  assert_true(@cache.entry_key("b.js", "h1", "r1", "0.1.0") != base)
  assert_true(@cache.entry_key("a.js", "h2", "r1", "0.1.0") != base)
  assert_true(@cache.entry_key("a.js", "h1", "r2", "0.1.0") != base)
  assert_true(@cache.entry_key("a.js", "h1", "r1", "0.2.0") != base)
}

///|
test "entry: finding roundtrip keeps every field" {
  let f = sample_finding()
  let back = @cache.from_cached(@cache.to_cached(f))
  assert_eq(back.rule_id, f.rule_id)
  assert_eq(back.severity, f.severity)
  assert_eq(back.confidence, f.confidence)
  assert_eq(back.cwe, f.cwe)
  assert_eq(back.owasp, f.owasp)
  assert_eq(back.primary, f.primary)
  assert_eq(back.message, f.message)
  assert_eq(back.snippet, f.snippet)
  assert_eq(back.fingerprint, f.fingerprint)
}

///|
async test "store: save then load hits, then invalidates on each guard" {
  let dir = ".tmp-cache-unit"
  let _ = @fs.rmdir(dir, recursive=true, allow_missing=true) catch { _ => () }
  let entry = @cache.make_entry(
    "src/a.js",
    "h1",
    "r1",
    "0.1.0",
    42,
    1,
    [sample_finding()],
    [],
  )
  @cache.save(dir, entry)
  let key = @cache.entry_key("src/a.js", "h1", "r1", "0.1.0")
  assert_true(@cache.load(dir, key, "src/a.js", "h1", "r1", "0.1.0") is Some(_))
  // content changed -> miss
  assert_true(@cache.load(dir, key, "src/a.js", "h2", "r1", "0.1.0") is None)
  // rules changed -> miss
  assert_true(@cache.load(dir, key, "src/a.js", "h1", "r2", "0.1.0") is None)
  // analyzer changed -> miss
  assert_true(@cache.load(dir, key, "src/a.js", "h1", "r1", "9.9.9") is None)
  // path changed -> miss
  assert_true(@cache.load(dir, key, "src/b.js", "h1", "r1", "0.1.0") is None)
  let hit = @cache.load(dir, key, "src/a.js", "h1", "r1", "0.1.0").unwrap()
  assert_eq(hit.bytes, 42)
  assert_eq(hit.findings.length(), 1)
  let _ = @fs.rmdir(dir, recursive=true, allow_missing=true) catch { _ => () }
}

///|
async test "store: missing and corrupt entries are misses, never errors" {
  let dir = ".tmp-cache-missing"
  let key = @cache.entry_key("x.js", "h", "r", "v")
  assert_true(@cache.load(dir, key, "x.js", "h", "r", "v") is None)
  @fs.mkdir(dir, recursive=true, allow_exist=true)
  @fs.write_file(@cache.cache_path(dir, key), "{not json")
  assert_true(@cache.load(dir, key, "x.js", "h", "r", "v") is None)
  let _ = @fs.rmdir(dir, recursive=true, allow_missing=true) catch { _ => () }
}
