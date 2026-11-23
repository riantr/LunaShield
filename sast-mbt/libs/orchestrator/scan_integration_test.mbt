///|
/// Minimal one-rule pack: JS001 (`eval` with a non-quoted argument), matching the
/// shape rules-validate insists on so the pack exercises the real parse path.
fn js_pack_json() -> String {
  "[" +
  "{\"id\":\"JS001\",\"language\":\"javascript\",\"severity\":\"high\"," +
  "\"cwe\":[95],\"owasp\":[\"A03:2021\"]," +
  "\"query\":\"(call_expression function: (identifier) @callee arguments: (arguments . (_) @arg)) @call\"," +
  "\"predicates\":[{\"kind\":\"text_equals\",\"capture\":\"callee\",\"value\":\"eval\"}]," +
  "\"message\":\"Dynamic code execution via eval()\",\"enabled\":true}" +
  "]"
}

///|
fn js_taint_json() -> String {
  "{\"version\":\"1.0.0\",\"languages\":[{\"language\":\"javascript\"," +
  "\"sources\":[{\"name\":\"http_query\",\"node_kind\":\"member_expression\"," +
  "\"text_contains\":\"req.query\"}]," +
  "\"sanitizers\":[{\"name\":\"escape_html\",\"callee_contains\":\"escapeHtml\"}]," +
  "\"sinks\":[{\"rule_id\":\"JS001\",\"capture\":\"arg\"}]}]}"
}

///|
/// Three files: `a.js` reaches the sink from `req.query` (confirmed), `b.js` is
/// clean, `c.js` assembles the flow through a sanitizer (sanitized).
async fn setup_case(name : String) -> String {
  let dir = ".tmp-orch-" + name
  let _ = @fs.rmdir(dir, recursive=true, allow_missing=true) catch { _ => () }
  @fs.mkdir(dir + "/src", recursive=true, allow_exist=true)
  @fs.write_file(dir + "/rules.json", js_pack_json())
  @fs.write_file(dir + "/src/a.js", "function f(req) { eval(req.query.x); }\n")
  @fs.write_file(dir + "/src/b.js", "function g(a, b) { return a + b; }\n")
  @fs.write_file(
    dir + "/src/c.js",
    "function h(req) { eval(escapeHtml(req.query.x)); }\n",
  )
  dir
}

///|
async fn cleanup(dir : String) -> Unit {
  let _ = @fs.rmdir(dir, recursive=true, allow_missing=true) catch { _ => () }
}

///|
fn js_config(dir : String) -> @config.ScanConfig {
  {
    ..@config.default_config(dir),
    rules_path: dir + "/rules.json",
    langs: ["javascript"],
  }
}

///|
/// Run a scan and return its error message, or "" when it succeeded.
async fn scan_error(cfg : @config.ScanConfig) -> String {
  try {
    let _ = @orchestrator.scan(cfg)
    ""
  } catch {
    @orchestrator.ScanError(message~) => message
    _ => "unexpected error"
  }
}

///|
async test "scan: end to end finds the sink and skips clean files" {
  let dir = setup_case("e2e")
  let outcome = @orchestrator.scan(js_config(dir)) catch {
    _ => abort("scan should succeed")
  }
  assert_eq(outcome.rule_count, 1)
  assert_eq(outcome.result.stats.files_scanned, 3)
  // a.js and c.js reach `eval`, b.js does not.
  assert_eq(outcome.result.findings.length(), 2)
  assert_eq(outcome.result.findings[0].primary.path, "src/a.js")
  assert_eq(outcome.result.findings[1].primary.path, "src/c.js")
  assert_eq(outcome.cache_hits, 0)
  assert_eq(outcome.cache_misses, 0)
  cleanup(dir)
}

///|
async test "scan: incremental cache misses then hits on the second run" {
  let dir = setup_case("cache")
  let cfg = { ..js_config(dir), incremental: true, cache_dir: dir + "/cache", }
  let first = @orchestrator.scan(cfg) catch { _ => abort("first scan failed") }
  assert_eq(first.cache_misses, 3)
  assert_eq(first.cache_hits, 0)
  let second = @orchestrator.scan(cfg) catch {
    _ => abort("second scan failed")
  }
  assert_eq(second.cache_misses, 0)
  assert_eq(second.cache_hits, 3)
  // Replay must reproduce the same findings, not just the same count.
  assert_eq(second.result.findings.length(), first.result.findings.length())
  for i in 0..<first.result.findings.length() {
    assert_eq(
      second.result.findings[i].fingerprint,
      first.result.findings[i].fingerprint,
    )
  }
  cleanup(dir)
}

///|
async test "scan: taint report annotates confidence, strict drops refuted" {
  let dir = setup_case("taint")
  @fs.write_file(dir + "/taint.json", js_taint_json())
  let report = @orchestrator.scan({
    ..js_config(dir),
    taint_mode: @config.Report,
  }) catch {
    _ => abort("report scan failed")
  }
  assert_eq(report.result.findings.length(), 2)
  assert_eq(report.result.findings[0].confidence, @core.High) // a.js confirmed
  assert_eq(report.result.findings[1].confidence, @core.Low) // c.js sanitized
  let strict = @orchestrator.scan({
    ..js_config(dir),
    taint_mode: @config.Strict,
  }) catch {
    _ => abort("strict scan failed")
  }
  assert_eq(strict.result.findings.length(), 1)
  assert_eq(strict.result.findings[0].primary.path, "src/a.js")
  cleanup(dir)
}

///|
async test "scan: empty rulepack is a setup error" {
  let dir = setup_case("empty")
  @fs.write_file(dir + "/rules.json", "[]")
  let message = scan_error(js_config(dir))
  assert_true(message.contains("no enabled rules"))
  cleanup(dir)
}

///|
async test "scan: a broken taint manifest aborts when taint is enabled" {
  let dir = setup_case("badtaint")
  @fs.write_file(
    dir + "/taint.json",
    "{\"version\":\"1.0.0\",\"languages\":[]}",
  )
  let message = scan_error({ ..js_config(dir), taint_mode: @config.Report, })
  assert_true(message.contains("taint"))
  cleanup(dir)
}

///|
async test "scan: shards partition files and stay deterministic" {
  let dir = setup_case("shard")
  let shard_a = @orchestrator.scan({
    ..js_config(dir),
    shard_index: 0,
    shard_total: 2,
  }) catch {
    _ => abort("shard 0 failed")
  }
  let shard_b = @orchestrator.scan({
    ..js_config(dir),
    shard_index: 1,
    shard_total: 2,
  }) catch {
    _ => abort("shard 1 failed")
  }
  assert_eq(
    shard_a.result.stats.files_scanned + shard_b.result.stats.files_scanned,
    3,
  )
  // Same shard twice must produce the same set of files.
  let again = @orchestrator.scan({
    ..js_config(dir),
    shard_index: 0,
    shard_total: 2,
  }) catch {
    _ => abort("shard 0 rerun failed")
  }
  assert_eq(
    again.result.stats.files_scanned,
    shard_a.result.stats.files_scanned,
  )
  cleanup(dir)
}

///|
async test "load_rule_pack: missing, malformed and schema-invalid packs error" {
  let dir = setup_case("packerr")
  let missing = try {
    let _ = @orchestrator.load_rule_pack(dir + "/nope.json")
    ""
  } catch {
    @orchestrator.ScanError(message~) => message
    _ => "unexpected error"
  }
  assert_true(missing.contains("cannot read rules file"))
  @fs.write_file(dir + "/bad.json", "{not json")
  let bad = try {
    let _ = @orchestrator.load_rule_pack(dir + "/bad.json")
    ""
  } catch {
    @orchestrator.ScanError(message~) => message
    _ => "unexpected error"
  }
  assert_true(bad.contains("not valid JSON"))
  @fs.write_file(dir + "/schema.json", "[{\"id\":\"JS001\"}]")
  let schema = try {
    let _ = @orchestrator.load_rule_pack(dir + "/schema.json")
    ""
  } catch {
    @orchestrator.ScanError(message~) => message
    _ => "unexpected error"
  }
  assert_true(schema.contains("schema checks"))
  @fs.write_file(
    dir + "/idprefix.json",
    "[" +
    "{\"id\":\"XX001\",\"language\":\"javascript\",\"severity\":\"high\"," +
    "\"cwe\":[],\"owasp\":[],\"query\":\"(identifier) @x\"," +
    "\"predicates\":[],\"message\":\"m\",\"enabled\":true}" +
    "]",
  )
  let idset = try {
    let _ = @orchestrator.load_rule_pack(dir + "/idprefix.json")
    ""
  } catch {
    @orchestrator.ScanError(message~) => message
    _ => "unexpected error"
  }
  assert_true(idset.contains("rule-set checks"))
  cleanup(dir)
}

///|
async test "load_rule_pack: directory form loads rules.json and digests bytes" {
  let dir = setup_case("packdir")
  let from_dir = @orchestrator.load_rule_pack(dir) catch {
    _ => abort("directory pack failed")
  }
  let from_file = @orchestrator.load_rule_pack(dir + "/rules.json") catch {
    _ => abort("file pack failed")
  }
  assert_eq(from_dir.rules.length(), 1)
  assert_eq(from_dir.digest, from_file.digest)
  assert_true(from_dir.digest.length() == 64)
  let rules = @orchestrator.load_rules(dir) catch {
    _ => abort("load_rules failed")
  }
  assert_eq(rules.length(), 1)
  cleanup(dir)
}
