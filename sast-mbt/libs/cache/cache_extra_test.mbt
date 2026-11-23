///|
/// Cached DTO helpers: unknown enum names must fall back to the conservative
/// default rather than aborting a scan, and save() is best-effort by design
/// (a cache is an optimisation, never a correctness requirement).

///|
test "cached: unknown enum strings fail soft to High" {
  let cached = @cache.to_cached(sample_finding())
  let broken : @cache.CachedFinding = {
    ..cached,
    severity: "bogus",
    confidence: "bogus",
  }
  let back = @cache.from_cached(broken)
  assert_eq(back.severity, @core.High)
  assert_eq(back.confidence, @core.High)
}

///|
test "cached: warning conversion roundtrips" {
  let w : @core.ParseWarning = {
    path: "a.js",
    line: 3,
    column: 2,
    message: "syntax error",
  }
  let back = @cache.warning_from_cached(@cache.cached_warning(w))
  assert_eq(back.path, w.path)
  assert_eq(back.line, w.line)
  assert_eq(back.column, w.column)
  assert_eq(back.message, w.message)
}

///|
async test "save: an impossible directory path fails soft" {
  // A NUL byte makes every filesystem call fail; a cache miss must never abort.
  let dir = "\u{0}invalid-cache-dir"
  let entry = @cache.make_entry("a.js", "h", "r", "t", "0.1.0", 1, 1, [], [])
  @cache.save(dir, entry)
  assert_true(true)
}
