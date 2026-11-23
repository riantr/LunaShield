// Scan orchestration: discover -> shard -> bounded-concurrency per-file scan ->
// deterministic aggregation. All ordering happens at the end, so task completion
// order can never leak into the report.

///|
/// Unrecoverable setup problems (rules missing / invalid). The CLI maps this to
/// exit code 2; per-file problems are warnings, not errors.
pub suberror ScanError {
  ScanError(message~ : String)
}

///|
/// Resolved taint manifest plus the digest that goes into the cache key. The
/// digest includes the mode name, so off/report/strict never share cached
/// findings even when they read the same manifest.
priv struct TaintSetup {
  spec : @taint.TaintSpec?
  digest : String
}

///|
/// Result of one scan plus bookkeeping the CLI prints (rule count, cache stats).
pub(all) struct ScanOutcome {
  result : @core.ScanResult
  rule_count : Int32
  cache_hits : Int32
  cache_misses : Int32
}

///|
/// Per-file scan output. `skipped` is `Some("path (reason)")` when the file was
/// deliberately not analyzed.
priv struct FileScan {
  findings : Array[@core.Finding]
  raw_hits : Int32
  warnings : Array[@core.ParseWarning]
  skipped : String?
  bytes : Int32
  cache_hit : Bool
}

///|
/// Everything `scan_one` needs to consult the incremental cache.
priv struct CacheCtx {
  dir : String
  rules_digest : String
  taint_digest : String
  analyzer_version : String
  /// Trust `(size, mtime)` probes and skip reading unchanged files.
  fast_cache : Bool
}

///|
fn rules_file(rules_path : String) -> String {
  if rules_path.has_suffix(".json") {
    rules_path
  } else {
    rules_path + "/rules.json"
  }
}

///|
/// A loaded rule pack: the enabled rules plus the digest used as a cache key
/// component. The digest is over the raw file bytes, so editing a rule without
/// bumping `manifest.json` still invalidates every cache entry.
pub(all) struct RulePack {
  rules : Array[@rule.Rule]
  digest : String
}

///|
/// Load and validate a rule pack. Accepts either a `rules.json` file or a
/// directory containing one.
pub async fn load_rule_pack(rules_path : String) -> RulePack {
  let path = rules_file(rules_path)
  let text = @fs.read_file(path).text() catch {
    _ => raise ScanError(message="cannot read rules file: \{path}")
  }
  let parsed = @json.parse(text) catch {
    e => raise ScanError(message="rules file is not valid JSON: \{path}: \{e}")
  }
  let rules = @rule.parse_rules(parsed) catch {
    @rule.RuleError(path~, message~) =>
      raise ScanError(
        message="rules file failed schema checks: \{path}: \{message}",
      )
  }
  @rule.validate_rule_set(rules) catch {
    @rule.RuleError(path~, message~) =>
      raise ScanError(
        message="rules file failed rule-set checks: \{path}: \{message}",
      )
  }
  let enabled : Array[@rule.Rule] = []
  for r in rules {
    if r.enabled {
      enabled.push(r)
    }
  }
  { rules: enabled, digest: @source-file.sha256_hex(text), }
}

///|
/// Enabled rules only, for callers that do not need the cache digest.
pub async fn load_rules(rules_path : String) -> Array[@rule.Rule] {
  load_rule_pack(rules_path).rules
}

///|
/// Last POSIX or Windows separator in a path, whichever comes later. Paths
/// arrive from the CLI verbatim, so `D:\pack\rules.json` must resolve its
/// sibling manifest just as `pack/rules.json` does.
fn last_separator(path : String) -> Int32? {
  let slash = path.rev_find("/")
  let backslash = path.rev_find("\\")
  match (slash, backslash) {
    (Some(a), Some(b)) => if a > b { Some(a) } else { Some(b) }
    (Some(a), None) => Some(a)
    (None, Some(b)) => Some(b)
    (None, None) => None
  }
}

///|
/// `taint.json` sits next to `rules.json` (or directly in the pack directory).
pub fn taint_file(rules_path : String) -> String {
  if rules_path.has_suffix(".json") {
    match last_separator(rules_path) {
      Some(i) => rules_path[:i + 1].to_owned() + "taint.json"
      None => "taint.json"
    }
  } else {
    let sep = match rules_path.rev_find("\\") {
      Some(_) => "\\"
      None => "/"
    }
    rules_path + sep + "taint.json"
  }
}

///|
/// Load the optional taint manifest. A missing file is a no-op — the safe
/// default that keeps pre-S4b behaviour — while a malformed or inconsistent
/// one is a setup error when the user explicitly asked for taint analysis.
async fn load_taint(
  rules_path : String,
  rule_ids : Array[String],
  mode : @config.TaintMode,
) -> TaintSetup {
  let prefix = @config.taint_mode_name(mode)
  if mode == @config.Off {
    return { spec: None, digest: prefix, }
  }
  let path = taint_file(rules_path)
  let text = @fs.read_file(path).text() catch {
    _ => return { spec: None, digest: prefix + "|none", }
  }
  let value = @json.parse(text) catch {
    e => raise ScanError(message="taint file is not valid JSON: \{path}: \{e}")
  }
  let spec = @taint.parse_spec(value) catch {
    @taint.TaintSpecError(message~) =>
      raise ScanError(
        message="taint file failed schema checks: \{path}: \{message}",
      )
  }
  @taint.validate_spec(spec, rule_ids) catch {
    @taint.TaintSpecError(message~) =>
      raise ScanError(
        message="taint file failed validation: \{path}: \{message}",
      )
  }
  { spec: Some(spec), digest: prefix + "|" + @source-file.sha256_hex(text), }
}

///|
/// Union of the extensions of the requested languages.
fn extensions_for(langs : Array[String]) -> Array[String] {
  let out : Array[String] = []
  for id in langs {
    match @lang.spec_by_id(id) {
      Some(spec) =>
        for e in spec.extensions {
          out.push(e)
        }
      None => ()
    }
  }
  out
}

///|
/// Join the scan root with a root-relative path for IO. Reports always use the
/// relative form, so this is the only place absolute-ish paths may appear.
fn fs_path(root : String, rel : String) -> String {
  if root == "" || root == "." {
    return rel
  }
  let mut base = root
  while base.length() > 1 && base.rev_find("/") == Some(base.length() - 1) {
    base = base[:base.length() - 1].to_owned()
  }
  base + "/" + rel
}

///|
/// Replay a cached result without reading the file body.
///
/// Returns `None` on any miss (no probe, stale entry, oversized file, stat
/// failure) so the caller falls back to the strict path — which also produces
/// the correct Skip reason for files this path declines to handle.
async fn fast_cached_scan(
  root : String,
  path : String,
  max_bytes : Int32,
  ctx : CacheCtx,
) -> FileScan? {
  let abs = fs_path(root, path)
  let size = @fs.file_size(abs) catch { _ => return None }
  if size > max_bytes.to_int64() {
    return None
  }
  let (mtime_sec, mtime_nsec) = @fs.mtime(abs) catch { _ => return None }
  let probe = match
    @cache.load_probe(ctx.dir, path, size, mtime_sec, mtime_nsec) {
    Some(p) => p
    None => return None
  }
  let entry = match
    @cache.load(
      ctx.dir,
      probe.entry_key,
      path,
      probe.content_hash,
      ctx.rules_digest,
      ctx.taint_digest,
      ctx.analyzer_version,
    ) {
    Some(e) => e
    None => return None
  }
  Some({
    findings: entry.findings.map(@cache.from_cached),
    raw_hits: entry.raw_hits,
    warnings: entry.warnings.map(@cache.warning_from_cached),
    skipped: None,
    bytes: entry.bytes,
    cache_hit: true,
  })
}

///|
/// Full pipeline for one file: read, parse, run rules, drop suppressed hits,
/// then (optionally) persist or reuse a cache entry.
async fn scan_one(
  root : String,
  path : String,
  rules : Array[@rule.Rule],
  max_bytes : Int32,
  cache : CacheCtx?,
  taint_spec : @taint.TaintSpec?,
  taint_mode : @config.TaintMode,
) -> FileScan {
  match cache {
    Some(ctx) =>
      if ctx.fast_cache {
        match fast_cached_scan(root, path, max_bytes, ctx) {
          Some(fs) => return fs
          None => ()
        }
      }
    None => ()
  }
  match @source-file.read_source(fs_path(root, path), max_bytes) {
    @source-file.Skip(reason) =>
      {
        findings: [],
        raw_hits: 0,
        warnings: [],
        skipped: Some("\{path} (\{@source-file.skip_reason_name(reason)})"),
        bytes: 0,
        cache_hit: false,
      }
    @source-file.Text(text) => {
      let spec = match @lang.spec_by_path(path) {
        Some(s) => s
        None =>
          return {
            findings: [],
            raw_hits: 0,
            warnings: [],
            skipped: Some("\{path} (unregistered-language)"),
            bytes: 0,
            cache_hit: false,
          }
      }
      let bytes = @source-file.byte_len(text)
      let ctx = match cache {
        Some(c) => c
        None => {
          let fs = analyze(
            path, spec, text, rules, bytes, taint_spec, taint_mode,
          )
          return fs
        }
      }
      // Cache lookups still read the file (the key is content-addressed); what
      // they skip is parsing and Query execution, which dominate CPU time.
      let content_hash = @source-file.sha256_hex(text)
      let key = @cache.entry_key(
        path,
        content_hash,
        ctx.rules_digest,
        ctx.taint_digest,
        ctx.analyzer_version,
      )
      match
        @cache.load(
          ctx.dir,
          key,
          path,
          content_hash,
          ctx.rules_digest,
          ctx.taint_digest,
          ctx.analyzer_version,
        ) {
        Some(entry) =>
          {
            findings: entry.findings.map(@cache.from_cached),
            raw_hits: entry.raw_hits,
            warnings: entry.warnings.map(@cache.warning_from_cached),
            skipped: None,
            bytes: entry.bytes,
            cache_hit: true,
          }
        None => {
          let fs = analyze(
            path, spec, text, rules, bytes, taint_spec, taint_mode,
          )
          @cache.save(
            ctx.dir,
            @cache.make_entry(
              path,
              content_hash,
              ctx.rules_digest,
              ctx.taint_digest,
              ctx.analyzer_version,
              fs.bytes,
              fs.raw_hits,
              fs.findings,
              fs.warnings,
            ),
          )
          // Record the probe so a later --fast-cache run can skip reading this
          // file. Only written when the fast path is on, so the default cache
          // layout is unchanged.
          if ctx.fast_cache {
            let size = @fs.file_size(fs_path(root, path)) catch {
              _ => return fs
            }
            let (mtime_sec, mtime_nsec) = @fs.mtime(fs_path(root, path)) catch {
              _ => return fs
            }
            @cache.save_probe(ctx.dir, {
              path,
              size,
              mtime_sec,
              mtime_nsec,
              content_hash,
              entry_key: key,
            })
          }
          fs
        }
      }
    }
  }
}

///|
/// Parse + query + taint verdict + suppress, without touching the cache.
/// `Off` never calls the analyzer: every hit stays `NotApplicable`, so the
/// pre-S4b output is reproduced exactly. `Strict` drops only verdicts the
/// analyzer actively refuted; `NotApplicable` findings are always preserved.
fn analyze(
  path : String,
  spec : @lang.LanguageSpec,
  text : String,
  rules : Array[@rule.Rule],
  bytes : Int32,
  taint_spec : @taint.TaintSpec?,
  taint_mode : @config.TaintMode,
) -> FileScan {
  let parsed = @parser.parse(spec, text, path)
  let suppressions = @scoring.parse_suppressions(text)
  let run = @query-engine.run_rules(parsed, rules)
  let findings : Array[@core.Finding] = []
  for h in run.hits {
    let mut hit = h
    if taint_mode != @config.Off {
      match taint_spec {
        Some(manifest) => {
          let result = @taint.analyze_with_spec(parsed, hit, manifest)
          hit = { ..hit, taint: result.verdict, }
        }
        None => ()
      }
    }
    if taint_mode == @config.Strict && @scoring.is_weak_verdict(hit.taint) {
      continue
    }
    if !@scoring.is_hit_suppressed(suppressions, hit.primary.line, hit.rule_id) {
      findings.push(@scoring.finding_from_hit(hit))
    }
  }
  let warnings = parsed.warnings
  for fail in run.failures {
    warnings.push({
      path,
      line: 1,
      column: 1,
      message: "rule \{fail.rule_id}: \{fail.message}",
    })
  }
  {
    findings,
    raw_hits: run.hits.length().to_int(),
    warnings,
    skipped: None,
    bytes,
    cache_hit: false,
  }
}

///|
fn cmp_str(a : String, b : String) -> Int32 {
  a[:].lexical_compare(b[:]).to_int()
}

///|
fn cmp_i32(a : Int32, b : Int32) -> Int32 {
  if a < b {
    -1
  } else if a > b {
    1
  } else {
    0
  }
}

///|
fn compare_warnings(a : @core.ParseWarning, b : @core.ParseWarning) -> Int32 {
  let by_path = cmp_str(a.path, b.path)
  if by_path != 0 {
    return by_path
  }
  let by_line = cmp_i32(a.line, b.line)
  if by_line != 0 {
    return by_line
  }
  cmp_i32(a.column, b.column)
}

///|
fn effective_concurrency(requested : Int32) -> Int32 {
  if requested > 0 {
    requested
  } else {
    4
  }
}

///|
/// Run a full scan. Files are discovered once, filtered by shard and language,
/// then processed concurrently with a semaphore cap. Aggregation is sorted, so
/// the output is identical across runs and across thread schedules.
///
/// `analyzer_version` participates in the cache key so a new build never reuses
/// results produced by different logic.
pub async fn scan(
  config : @config.ScanConfig,
  analyzer_version? : String,
) -> ScanOutcome {
  let pack = load_rule_pack(config.rules_path)
  let rules = pack.rules
  if rules.length() == 0 {
    raise ScanError(
      message="no enabled rules in \{rules_file(config.rules_path)}",
    )
  }
  let analyzer = match analyzer_version {
    Some(v) => v
    None => "0.1.0"
  }
  let taint = load_taint(
    config.rules_path,
    rules.map(fn(r) { r.id }),
    config.taint_mode,
  )
  let cache : CacheCtx? = if config.incremental {
    Some({
      dir: config.cache_dir,
      rules_digest: pack.digest,
      taint_digest: taint.digest,
      analyzer_version: analyzer,
      fast_cache: config.fast_cache,
    })
  } else {
    None
  }
  let extensions = extensions_for(config.langs)
  let discovered = @source-file.discover(
    config.root,
    extensions,
    [".gitignore", ".sastignore"],
    extra_patterns=config.ignore_patterns,
  )
  let files : Array[String] = []
  for path in discovered.files {
    if @config.in_shard(config, path) {
      files.push(path)
    }
  }
  let skipped : Array[String] = []
  for s in discovered.skipped {
    skipped.push("\{s.path} (\{@source-file.skip_reason_name(s.reason)})")
  }

  let results : Array[FileScan] = []
  let sem = @semaphore.Semaphore(effective_concurrency(config.max_concurrency))
  @async.with_task_group <| group => {
    for path in files {
      group.spawn_bg(() => {
        sem.acquire()
        defer sem.release()
        let fs = scan_one(
          config.root,
          path,
          rules,
          @source-file.DEFAULT_MAX_BYTES,
          cache,
          taint.spec,
          config.taint_mode,
        )
        results.push(fs)
      })
    }
  }

  let findings : Array[@core.Finding] = []
  let warnings : Array[@core.ParseWarning] = []
  let mut raw_hits : Int32 = 0
  let mut bytes_scanned : Int32 = 0
  let mut scanned : Int32 = 0
  let mut cache_hits : Int32 = 0
  let mut cache_misses : Int32 = 0
  for fs in results {
    for f in fs.findings {
      findings.push(f)
    }
    for w in fs.warnings {
      warnings.push(w)
    }
    match fs.skipped {
      Some(s) => skipped.push(s)
      None => {
        scanned += 1
        bytes_scanned += fs.bytes
        raw_hits += fs.raw_hits
        // Cache statistics only exist when the cache does: a non-incremental
        // scan must not report every file as a miss.
        match cache {
          Some(_) =>
            if fs.cache_hit {
              cache_hits += 1
            } else {
              cache_misses += 1
            }
          None => ()
        }
      }
    }
  }
  warnings.mut_view().sort_by(compare_warnings)
  skipped.sort_by_key(fn(s) { s })
  let finalized = @scoring.finalize_findings(findings, raw_hits)
  let result : @core.ScanResult = {
    findings: finalized.findings,
    warnings,
    skipped_files: skipped,
    stats: {
      files_scanned: scanned,
      files_skipped: skipped.length().to_int(),
      bytes_scanned,
      raw_hits: finalized.stats.raw_hits,
      duration_ms: 0,
    },
  }
  { result, rule_count: rules.length(), cache_hits, cache_misses, }
}
