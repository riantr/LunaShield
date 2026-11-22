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
/// Result of one scan plus the number of rules that were actually applied.
pub(all) struct ScanOutcome {
  result : @core.ScanResult
  rule_count : Int32
}

///|
/// Per-file scan output. `skipped` is `Some("path (reason)")` when the file was
/// deliberately not analyzed.
priv struct FileScan {
  hits : Array[@core.RawHit]
  warnings : Array[@core.ParseWarning]
  skipped : String?
  bytes : Int32
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
/// Load and validate a rule pack. Accepts either a `rules.json` file or a
/// directory containing one.
pub async fn load_rules(rules_path : String) -> Array[@rule.Rule] {
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
  enabled
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
/// Scan one file: read, parse, run rules, drop suppressed hits.
async fn scan_one(
  root : String,
  path : String,
  rules : Array[@rule.Rule],
  max_bytes : Int32,
) -> FileScan {
  match @source-file.read_source(fs_path(root, path), max_bytes) {
    @source-file.Skip(reason) =>
      {
        hits: [],
        warnings: [],
        skipped: Some("\{path} (\{@source-file.skip_reason_name(reason)})"),
        bytes: 0,
      }
    @source-file.Text(text) => {
      let spec = match @lang.spec_by_path(path) {
        Some(s) => s
        None =>
          return {
            hits: [],
            warnings: [],
            skipped: Some("\{path} (unregistered-language)"),
            bytes: 0,
          }
      }
      let parsed = @parser.parse(spec, text, path)
      let suppressions = @scoring.parse_suppressions(text)
      let run = @query-engine.run_rules(parsed, rules)
      let kept : Array[@core.RawHit] = []
      for h in run.hits {
        if !@scoring.is_hit_suppressed(suppressions, h.primary.line, h.rule_id) {
          kept.push(h)
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
        hits: kept,
        warnings,
        skipped: None,
        bytes: @source-file.byte_len(text),
      }
    }
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
pub async fn scan(config : @config.ScanConfig) -> ScanOutcome {
  let rules = load_rules(config.rules_path)
  if rules.length() == 0 {
    raise ScanError(
      message="no enabled rules in \{rules_file(config.rules_path)}",
    )
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

  let hits : Array[@core.RawHit] = []
  let warnings : Array[@core.ParseWarning] = []
  let sizes : Array[Int32] = []
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
        )
        for h in fs.hits {
          hits.push(h)
        }
        for w in fs.warnings {
          warnings.push(w)
        }
        match fs.skipped {
          Some(s) => skipped.push(s)
          None => sizes.push(fs.bytes)
        }
      })
    }
  }

  let mut bytes_scanned : Int32 = 0
  for n in sizes {
    bytes_scanned += n
  }
  warnings.mut_view().sort_by(compare_warnings)
  skipped.sort_by_key(fn(s) { s })
  let finalized = @scoring.finalize(hits)
  let result : @core.ScanResult = {
    findings: finalized.findings,
    warnings,
    skipped_files: skipped,
    stats: {
      files_scanned: sizes.length().to_int(),
      files_skipped: skipped.length().to_int(),
      bytes_scanned,
      raw_hits: finalized.stats.raw_hits,
      duration_ms: 0,
    },
  }
  { result, rule_count: rules.length(), }
}
