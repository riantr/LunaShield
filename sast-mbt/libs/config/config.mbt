///|
/// Immutable scan configuration. CLI parsing is added in M4; M1 defines the model
/// and defaults so downstream packages can depend on a stable shape.
#derive(Debug, Eq)
pub(all) enum FailOn {
  Never
  Threshold(@core.Severity)
}

///|
pub(all) struct ScanConfig {
  root : String
  langs : Array[String]
  rules_path : String
  formats : Array[String]
  out_dir : String
  fail_on : FailOn
  shard_index : Int32
  shard_total : Int32
  ignore_patterns : Array[String]
  max_concurrency : Int32
  incremental : Bool
  rulepack_version : String
}

///|
/// All registered language keys, used as the default language filter.
pub fn all_languages() -> Array[String] {
  ["javascript", "typescript", "tsx", "python", "java", "json"]
}

///|
/// Conservative defaults matching the MVP CLI contract (§6).
pub fn default_config(root : String) -> ScanConfig {
  ScanConfig::{
    root,
    langs: all_languages(),
    rules_path: "rulepacks/official",
    formats: ["console", "json"],
    out_dir: "",
    fail_on: Threshold(@core.High),
    shard_index: 0,
    shard_total: 1,
    ignore_patterns: [],
    max_concurrency: 0,
    incremental: false,
    rulepack_version: "",
  }
}

///|
/// Parse `--fail-on` values: never|critical|high|medium|low|info.
pub fn parse_fail_on(s : String) -> FailOn? {
  if s == "never" {
    return Some(Never)
  }
  match @core.severity_from_string(s) {
    Some(sev) => Some(Threshold(sev))
    None => None
  }
}

///|
/// Whether a finding's severity meets the configured gate.
pub fn meets_fail_on(config : ScanConfig, severity : @core.Severity) -> Bool {
  match config.fail_on {
    Never => false
    Threshold(threshold) =>
      @core.severity_rank(severity) >= @core.severity_rank(threshold)
  }
}

///|
/// Whether a shard configuration is valid (0 <= i < n, n >= 1).
pub fn valid_shard(config : ScanConfig) -> Bool {
  config.shard_total >= 1 &&
  config.shard_index >= 0 &&
  config.shard_index < config.shard_total
}

///|
/// Deterministic shard assignment: hash(relative_path) % shard_total == shard_index.
/// Uses FNV-1a over UTF-8 bytes so Linux and Windows agree.
pub fn in_shard(config : ScanConfig, relative_path : String) -> Bool {
  if config.shard_total <= 1 {
    return true
  }
  let mut hash : UInt64 = 14695981039346656037UL
  for b in @utf8.encode(relative_path) {
    hash = (hash ^ b.to_uint64()) * 1099511628211UL
  }
  (hash % config.shard_total.to_uint64()).to_int() == config.shard_index
}
