// sast-mbt CLI. Exit codes: 0 clean, 1 findings at or above --fail-on,
// 2 config/rule/argument error, 3 unrecoverable scan error.

///|
fn usage() -> String {
  "usage: scan <root> [options]\n" +
  "  --lang <csv>          languages to scan (default: all)\n" +
  "  --rules <path>        rule pack directory or rules.json (default: rulepacks/official)\n" +
  "  --format <csv>        console,json,junit,sarif (default: console,json)\n" +
  "  --out <dir>           write reports into dir instead of stdout\n" +
  "  --fail-on <severity>  critical|high|medium|low|info|never (default: high)\n" +
  "  --shard <i>/<n>       scan only shard i of n\n" +
  "  --ignore <pattern>    extra ignore pattern (repeatable)\n" +
  "  --max-concurrency <n> per-file concurrency (default: 4)\n" +
  "  --incremental         reuse per-file results from --cache-dir\n" +
  "  --cache-dir <dir>     cache location (default: .lunashield-cache)\n" +
  "  --taint <mode>        off|report|strict taint analysis (default: off)\n"
}

///|
fn[T] fail(message : String) -> T {
  println("error: \{message}")
  @env.exit(2)
}

///|
fn split_csv(s : String) -> Array[String] {
  let out : Array[String] = []
  for raw in s.split(",") {
    let item = raw.trim().to_owned()
    if item.length() > 0 {
      out.push(item)
    }
  }
  out
}

///|
/// Minimal non-negative decimal parser (the stdlib strconv package is empty in
/// this toolchain build, so we own the three lines instead).
fn parse_uint(s : StringView) -> Int32? {
  guard s.length() > 0 else { return None }
  let mut n = 0
  for c in s {
    guard c >= '0' && c <= '9' else { return None }
    // ASCII '0' is 48; Char has no arithmetic, so subtract the code point.
    n = n * 10 + (c.to_uint().reinterpret_as_int() - 48)
  }
  Some(n)
}

///|
fn parse_shard(s : String) -> (Int32, Int32)? {
  let parts = match s.find("/") {
    Some(i) => [s[:i].to_owned(), s[i + 1:].to_owned()]
    None => return None
  }
  let index = match parse_uint(parts[0].trim()) {
    Some(n) => n
    None => return None
  }
  let total = match parse_uint(parts[1].trim()) {
    Some(n) => n
    None => return None
  }
  guard total >= 1 && index < total else { return None }
  Some((index, total))
}

///|
fn arg_or_fail(args : Array[String], i : Int32) -> String {
  if i + 1 >= args.length() {
    fail("option \{args[i]} needs a value")
  }
  args[i + 1]
}

///|
fn one_of(value : String, allowed : Array[String]) -> Bool {
  for a in allowed {
    if a == value {
      return true
    }
  }
  false
}

///|
async fn write_report(dir : String, name : String, content : String) -> Unit {
  @fs.mkdir(dir, recursive=true, allow_exist=true)
  @fs.write_file(dir + "/" + name, content)
}

///|
async fn main {
  let args = @env.args()
  let mut root = ""
  let mut cfg = @config.default_config(".")
  let mut out_dir = ""
  let ignore_patterns : Array[String] = []
  let mut i = 1
  while i < args.length() {
    let arg = args[i]
    if arg == "--help" || arg == "-h" {
      println(usage())
      @env.exit(0)
    } else if arg == "--lang" {
      let value = arg_or_fail(args, i)
      let langs = split_csv(value)
      guard langs.length() > 0 else {
        fail("--lang needs at least one language")
      }
      cfg = { ..cfg, langs, }
      i += 2
    } else if arg == "--rules" {
      let value = arg_or_fail(args, i)
      cfg = { ..cfg, rules_path: value, }
      i += 2
    } else if arg == "--format" {
      let value = arg_or_fail(args, i)
      let formats = split_csv(value)
      guard formats.length() > 0 else {
        fail("--format needs at least one format")
      }
      for f in formats {
        guard @report.reporter_for(f) is Some(_) else {
          fail(
            "unknown format '\{f}', expected \{@report.supported_formats().join(",")}",
          )
        }
      }
      cfg = { ..cfg, formats, }
      i += 2
    } else if arg == "--out" {
      out_dir = arg_or_fail(args, i)
      cfg = { ..cfg, out_dir, }
      i += 2
    } else if arg == "--fail-on" {
      let value = arg_or_fail(args, i)
      let parsed = match @config.parse_fail_on(value) {
        Some(f) => f
        None =>
          fail(
            "unknown severity '\{value}', expected critical|high|medium|low|info|never",
          )
      }
      cfg = { ..cfg, fail_on: parsed, }
      i += 2
    } else if arg == "--shard" {
      let value = arg_or_fail(args, i)
      let shard = match parse_shard(value) {
        Some(s) => s
        None =>
          fail("invalid shard '\{value}', expected <i>/<n> with 0 <= i < n")
      }
      cfg = { ..cfg, shard_index: shard.0, shard_total: shard.1, }
      i += 2
    } else if arg == "--ignore" {
      let value = arg_or_fail(args, i)
      ignore_patterns.push(value)
      i += 2
    } else if arg == "--incremental" {
      cfg = { ..cfg, incremental: true, }
      i += 1
    } else if arg == "--cache-dir" {
      let value = arg_or_fail(args, i)
      cfg = { ..cfg, cache_dir: value, }
      i += 2
    } else if arg == "--taint" {
      let value = arg_or_fail(args, i)
      let mode = match @config.parse_taint_mode(value) {
        Some(m) => m
        None =>
          fail("unknown taint mode '\{value}', expected off|report|strict")
      }
      cfg = { ..cfg, taint_mode: mode, }
      i += 2
    } else if arg == "--max-concurrency" {
      let value = arg_or_fail(args, i)
      let n = match parse_uint(value.trim()) {
        Some(n) => n
        None => fail("--max-concurrency needs a positive integer")
      }
      guard n >= 1 else { fail("--max-concurrency needs a positive integer") }
      cfg = { ..cfg, max_concurrency: n, }
      i += 2
    } else if arg.has_prefix("--") {
      fail("unknown option '\{arg}'")
    } else {
      guard root.length() == 0 else {
        fail("unexpected extra argument '\{arg}'")
      }
      root = arg
      i += 1
    }
  }
  guard root.length() > 0 else {
    println(usage())
    @env.exit(2)
  }
  cfg = { ..cfg, root, ignore_patterns, }

  let outcome = @orchestrator.scan(cfg) catch {
    @orchestrator.ScanError(message~) => {
      println("error: \{message}")
      @env.exit(2)
    }
    e => {
      println("error: scan failed: \{e}")
      @env.exit(3)
    }
  }

  // Emit in the canonical order from `supported_formats`, never in user CSV
  // order: mixed `--format` invocations must stay byte-stable.
  for fmt in @report.supported_formats() {
    if !one_of(fmt, cfg.formats) {
      continue
    }
    match @report.reporter_for(fmt) {
      None => ()
      Some(rep) => {
        let text = rep.render(outcome.result)
        match rep.file_name() {
          None => {
            println(text)
            if cfg.incremental && fmt == "console" {
              println(
                "cache: \{outcome.cache_hits} hit, \{outcome.cache_misses} miss",
              )
            }
          }
          Some(name) =>
            if out_dir.length() > 0 {
              write_report(out_dir, name, text + "\n")
            } else {
              println(text)
            }
        }
      }
    }
  }

  let mut gated = false
  for f in outcome.result.findings {
    if @config.meets_fail_on(cfg, f.severity) {
      gated = true
    }
  }
  if gated {
    @env.exit(1)
  }
  @env.exit(0)
}
