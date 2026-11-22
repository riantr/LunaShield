///|
fn hit(
  rule_id : String,
  path : String,
  line : Int32,
  column : Int32,
  snippet : String,
) -> @core.RawHit {
  hit_tainted(rule_id, path, line, column, snippet, @core.NotApplicable)
}

///|
fn hit_tainted(
  rule_id : String,
  path : String,
  line : Int32,
  column : Int32,
  snippet : String,
  taint : @core.TaintVerdict,
) -> @core.RawHit {
  {
    rule_id,
    language: "javascript",
    severity: @core.High,
    cwe: [95],
    owasp: ["A03:2021"],
    message: "Dynamic code execution via eval()",
    primary: { path, line, column, byte_offset: 0, },
    snippet,
    captures: Map([]),
    taint,
  }
}

///|
test "fingerprint: P0 baseline constant is reproduced byte for byte" {
  assert_eq(
    @scoring.make_fingerprint("JS001", "eval"),
    "cad6a9d402bd4d6c926a60f7d06d046c4fdf4b613dab5be32c2189e45cd3da31",
  )
}

///|
test "fingerprint: whitespace-only differences do not change the hash" {
  let base = @scoring.make_fingerprint("JS001", "eval(userInput)")
  assert_eq(@scoring.make_fingerprint("JS001", "  eval(userInput)\n"), base)
  assert_eq(
    @scoring.make_fingerprint("JS001", "eval(\n\tuserInput)"),
    @scoring.make_fingerprint("JS001", "eval( userInput)"),
  )
}

///|
test "normalize: trims and collapses internal whitespace runs" {
  assert_eq(@scoring.normalize_snippet("  eval(x)\n\t"), "eval(x)")
  assert_eq(@scoring.normalize_snippet("a\n\t b   c"), "a b c")
  assert_eq(@scoring.normalize_snippet(""), "")
  assert_eq(@scoring.normalize_snippet("   "), "")
}

///|
test "finalize: duplicate snippets collapse to one finding" {
  let hits = [
    hit("JS001", "danger.js", 2, 1, "eval"),
    hit("JS001", "danger.js", 4, 10, "eval"),
  ]
  let result = @scoring.finalize(hits)
  assert_eq(result.findings.length(), 1)
  assert_eq(result.stats.raw_hits, 2)
  let f = result.findings[0]
  assert_eq(f.rule_id, "JS001")
  assert_eq(f.severity, @core.High)
  assert_eq(f.confidence, @core.High)
  assert_eq(f.primary.line, 2)
  assert_eq(f.snippet, "eval")
  assert_eq(
    f.fingerprint,
    "cad6a9d402bd4d6c926a60f7d06d046c4fdf4b613dab5be32c2189e45cd3da31",
  )
}

///|
test "finalize: the same snippet in two files stays two findings" {
  let hits = [
    hit("JS001", "a.js", 1, 1, "eval"),
    hit("JS001", "b.js", 1, 1, "eval"),
  ]
  let result = @scoring.finalize(hits)
  assert_eq(result.findings.length(), 2)
  assert_eq(result.findings[0].primary.path, "a.js")
  assert_eq(result.findings[1].primary.path, "b.js")
  // Same fingerprint, different files — the pair is a real duplicate signal too.
  assert_eq(result.findings[0].fingerprint, result.findings[1].fingerprint)
}

///|
test "finalize: ordering is path, then line, then column" {
  let hits = [
    hit("JS001", "b.js", 1, 1, "eval"),
    hit("JS001", "a.js", 9, 2, "eval(x)"),
    hit("JS001", "a.js", 2, 7, "eval(y)"),
  ]
  let result = @scoring.finalize(hits)
  assert_eq(result.findings.length(), 3)
  assert_eq(result.findings[0].primary.path, "a.js")
  assert_eq(result.findings[0].primary.line, 2)
  assert_eq(result.findings[1].primary.path, "a.js")
  assert_eq(result.findings[1].primary.line, 9)
  assert_eq(result.findings[2].primary.path, "b.js")
}

///|
test "suppression: same line, next line and rule scoping" {
  let hits = [
    hit("JS001", "a.js", 3, 1, "eval"),
    hit("JS001", "a.js", 7, 1, "eval"),
    hit("JS002", "a.js", 9, 1, "eval"),
  ]
  let sups = @scoring.parse_suppressions(
    "line1\nline2\n// sast-ignore\nline4\nline5\n// sast-ignore-next-line\nline7\nline8\n// sast-ignore: JS002\n",
  )
  let result = @scoring.finalize_with(hits, sups)
  // line 3 suppressed by its own line, line 7 by the next-line directive on
  // line 6, line 9 by the rule-scoped directive on line 9.
  assert_eq(result.findings.length(), 0)
  assert_eq(result.stats.raw_hits, 3)
}

///|
test "suppression: rule-scoped directive does not silence other rules" {
  let hits = [hit("JS001", "a.js", 2, 1, "eval")]
  let sups = @scoring.parse_suppressions("line1\n// sast-ignore: JS002\n")
  let result = @scoring.finalize_with(hits, sups)
  assert_eq(result.findings.length(), 1)
}

///|
test "suppression: parser records target lines and rule lists" {
  let sups = @scoring.parse_suppressions(
    "a\n// sast-ignore\nb\n// sast-ignore-next-line: JS001, JS003\n",
  )
  assert_eq(sups.length(), 2)
  assert_eq(sups[0].line, 2)
  assert_eq(sups[0].rule_ids.length(), 0)
  assert_eq(sups[1].line, 5)
  assert_eq(sups[1].rule_ids, ["JS001", "JS003"])
}

///|
test "taint: verdict maps to confidence (NotApplicable keeps the baseline)" {
  assert_eq(@scoring.confidence_from_taint(@core.NotApplicable), @core.High)
  assert_eq(@scoring.confidence_from_taint(@core.Confirmed), @core.High)
  assert_eq(@scoring.confidence_from_taint(@core.Sanitized), @core.Low)
  assert_eq(@scoring.confidence_from_taint(@core.NoSource), @core.Low)
}

///|
test "taint: finding_from_hit carries verdict-derived confidence" {
  let confirmed = hit_tainted("JS001", "a.js", 1, 1, "eval", @core.Confirmed)
  let sanitized = hit_tainted("JS001", "b.js", 1, 1, "eval", @core.Sanitized)
  let no_source = hit_tainted("JS001", "c.js", 1, 1, "eval", @core.NoSource)
  assert_eq(@scoring.finding_from_hit(confirmed).confidence, @core.High)
  assert_eq(@scoring.finding_from_hit(sanitized).confidence, @core.Low)
  assert_eq(@scoring.finding_from_hit(no_source).confidence, @core.Low)
  // severity and fingerprint are untouched by taint
  assert_eq(@scoring.finding_from_hit(sanitized).severity, @core.High)
  assert_eq(
    @scoring.finding_from_hit(sanitized).fingerprint,
    @scoring.make_fingerprint("JS001", "eval"),
  )
}

///|
test "taint: finalize downgrades refuted findings but keeps their count" {
  let hits = [
    hit_tainted("JS001", "a.js", 1, 1, "eval", @core.Confirmed),
    hit_tainted("JS001", "b.js", 1, 1, "eval", @core.Sanitized),
    hit_tainted("JS001", "c.js", 1, 1, "eval", @core.NoSource),
    hit_tainted("JS001", "d.js", 1, 1, "eval", @core.NotApplicable),
  ]
  let result = @scoring.finalize(hits)
  assert_eq(result.findings.length(), 4)
  assert_eq(result.findings[0].confidence, @core.High) // a.js confirmed
  assert_eq(result.findings[1].confidence, @core.Low) // b.js sanitized
  assert_eq(result.findings[2].confidence, @core.Low) // c.js no-source
  assert_eq(result.findings[3].confidence, @core.High) // d.js not-applicable
}

///|
test "taint: prune_by_taint drops only weak verdicts" {
  assert_true(@scoring.is_weak_verdict(@core.Sanitized))
  assert_true(@scoring.is_weak_verdict(@core.NoSource))
  assert_true(!@scoring.is_weak_verdict(@core.Confirmed))
  assert_true(!@scoring.is_weak_verdict(@core.NotApplicable))
  let hits = [
    hit_tainted("JS001", "a.js", 1, 1, "eval", @core.Confirmed),
    hit_tainted("JS001", "b.js", 1, 1, "eval", @core.Sanitized),
    hit_tainted("JS001", "c.js", 1, 1, "eval", @core.NoSource),
    hit_tainted("JS001", "d.js", 1, 1, "eval", @core.NotApplicable),
  ]
  let kept = @scoring.prune_by_taint(hits)
  assert_eq(kept.length(), 2)
  assert_eq(kept[0].primary.path, "a.js")
  assert_eq(kept[1].primary.path, "d.js")
  // Identity when taint was never run.
  let all_na = [hit("JS001", "a.js", 1, 1, "eval")]
  assert_eq(@scoring.prune_by_taint(all_na).length(), 1)
}
