// P2-S3: per-file result cache.
//
// The cache stores *finalized findings* (post-suppression, pre-cross-file-dedupe)
// rather than raw hits, so nothing in this module needs the query engine or the
// predicate layer. Validity is content-addressed:
//     key = sha256(path | content_hash | rules_digest | analyzer_version)
// so editing a rule pack (digest) or the analyzer invalidates every entry even
// when `manifest.json` forgets a version bump.

///|
/// Bumped to 2 in S4b-3: cached findings now carry `confidence`, so entries
/// written by the earlier schema would replay the old "always High" default.
/// Bumped to 3 in S4b-4: entries carry `taint_digest`, which also encodes the
/// taint mode, so switching `--taint` can never replay results from another mode.
pub const CACHE_SCHEMA : Int32 = 3

///|
pub const CACHE_FILE_SUFFIX : String = ".json"

///|
#derive(@json.ToJson, @json.FromJson)
pub(all) struct CachedFinding {
  rule_id : String
  severity : String
  /// Lowercase confidence name; absent/unknown values fall back to High on load.
  confidence : String
  cwe : Array[Int32]
  owasp : Array[String]
  message : String
  snippet : String
  fingerprint : String
  path : String
  line : Int32
  column : Int32
  byte_offset : Int32
}

///|
#derive(@json.ToJson, @json.FromJson)
pub(all) struct CachedWarning {
  path : String
  line : Int32
  column : Int32
  message : String
}

///|
#derive(@json.ToJson, @json.FromJson)
pub(all) struct CacheEntry {
  schema : Int32
  path : String
  content_hash : String
  rules_digest : String
  /// Mode name + sha256 of taint.json, or "off". Part of the key and checked
  /// on load, so changing the manifest or the mode invalidates the entry.
  taint_digest : String
  analyzer_version : String
  bytes : Int32
  raw_hits : Int32
  findings : Array[CachedFinding]
  warnings : Array[CachedWarning]
}

///|
fn sha256_hex(text : String) -> String {
  @bithash.hex_encode(@bithash.sha256_raw(@utf8.encode(text)))
}

///|
/// Cache key for one (file, rules, taint, analyzer) tuple. Pure function so
/// tests can assert stability and sensitivity without touching the filesystem.
pub fn entry_key(
  path : String,
  content_hash : String,
  rules_digest : String,
  taint_digest : String,
  analyzer_version : String,
) -> String {
  sha256_hex(
    path +
    "\u{0}" +
    content_hash +
    "\u{0}" +
    rules_digest +
    "\u{0}" +
    taint_digest +
    "\u{0}" +
    analyzer_version,
  )
}

///|
pub fn cache_path(cache_dir : String, key : String) -> String {
  cache_dir + "/" + key + CACHE_FILE_SUFFIX
}

///|
pub fn to_cached(f : @core.Finding) -> CachedFinding {
  {
    rule_id: f.rule_id,
    severity: @core.severity_name(f.severity),
    confidence: @core.confidence_name(f.confidence),
    cwe: f.cwe,
    owasp: f.owasp,
    message: f.message,
    snippet: f.snippet,
    fingerprint: f.fingerprint,
    path: f.primary.path,
    line: f.primary.line,
    column: f.primary.column,
    byte_offset: f.primary.byte_offset,
  }
}

///|
pub fn from_cached(c : CachedFinding) -> @core.Finding {
  {
    rule_id: c.rule_id,
    severity: match @core.severity_from_string(c.severity) {
      Some(s) => s
      None => @core.High
    },
    confidence: match @core.confidence_from_string(c.confidence) {
      Some(v) => v
      None => @core.High
    },
    cwe: c.cwe,
    owasp: c.owasp,
    primary: {
      path: c.path,
      line: c.line,
      column: c.column,
      byte_offset: c.byte_offset,
    },
    related: [],
    message: c.message,
    snippet: c.snippet,
    fingerprint: c.fingerprint,
  }
}

///|
pub fn cached_warning(w : @core.ParseWarning) -> CachedWarning {
  { path: w.path, line: w.line, column: w.column, message: w.message, }
}

///|
pub fn warning_from_cached(c : CachedWarning) -> @core.ParseWarning {
  { path: c.path, line: c.line, column: c.column, message: c.message, }
}

///|
/// Build an entry for a fresh scan of one file.
pub fn make_entry(
  path : String,
  content_hash : String,
  rules_digest : String,
  taint_digest : String,
  analyzer_version : String,
  bytes : Int32,
  raw_hits : Int32,
  findings : Array[@core.Finding],
  warnings : Array[@core.ParseWarning],
) -> CacheEntry {
  {
    schema: CACHE_SCHEMA,
    path,
    content_hash,
    rules_digest,
    taint_digest,
    analyzer_version,
    bytes,
    raw_hits,
    findings: findings.map(to_cached),
    warnings: warnings.map(cached_warning),
  }
}

///|
fn matches(
  entry : CacheEntry,
  path : String,
  content_hash : String,
  rules_digest : String,
  taint_digest : String,
  analyzer_version : String,
) -> Bool {
  entry.schema == CACHE_SCHEMA &&
  entry.path == path &&
  entry.content_hash == content_hash &&
  entry.rules_digest == rules_digest &&
  entry.taint_digest == taint_digest &&
  entry.analyzer_version == analyzer_version
}

///|
/// Load an entry and validate it against the current inputs. Any read/parse
/// failure or mismatch is a miss — the cache must never make a scan fail.
pub async fn load(
  cache_dir : String,
  key : String,
  path : String,
  content_hash : String,
  rules_digest : String,
  taint_digest : String,
  analyzer_version : String,
) -> CacheEntry? {
  let text = @fs.read_file(cache_path(cache_dir, key)).text() catch {
    _ => return None
  }
  let json = @json.parse(text) catch { _ => return None }
  let entry : CacheEntry = @json.from_json(json) catch { _ => return None }
  if matches(
      entry, path, content_hash, rules_digest, taint_digest, analyzer_version,
    ) {
    Some(entry)
  } else {
    None
  }
}

///|
/// Persist an entry. Write failures are swallowed: a broken cache directory must
/// degrade to "always miss", never to a failed scan.
pub async fn save(cache_dir : String, entry : CacheEntry) -> Unit {
  let key = entry_key(
    entry.path,
    entry.content_hash,
    entry.rules_digest,
    entry.taint_digest,
    entry.analyzer_version,
  )
  let text = @json.to_json(entry).stringify() + "\n"
  try {
    @fs.mkdir(cache_dir, recursive=true, allow_exist=true)
    @fs.write_file(cache_path(cache_dir, key), text)
  } catch {
    _ => ()
  }
}
