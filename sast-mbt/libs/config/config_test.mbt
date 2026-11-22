/// M1: ScanConfig model, defaults, gate threshold, deterministic sharding.

///|
test "default config matches MVP CLI contract" {
  let c = @config.default_config("/tmp/project")
  assert_eq(c.root, "/tmp/project")
  assert_eq(c.langs.length(), 6)
  assert_eq(c.rules_path, "rulepacks/official")
  assert_eq(c.formats, ["console", "json"])
  assert_eq(c.shard_index, 0)
  assert_eq(c.shard_total, 1)
  assert_eq(c.incremental, false)
  assert_true(@config.valid_shard(c))
}

///|
test "fail-on parsing and threshold gate" {
  assert_eq(@config.parse_fail_on("never"), Some(@config.Never))
  match @config.parse_fail_on("high") {
    Some(@config.Threshold(sev)) => assert_eq(sev, @core.High)
    _ => abort("expected high threshold")
  }
  assert_eq(@config.parse_fail_on("bogus"), None)

  let c = @config.default_config("x")
  assert_true(@config.meets_fail_on(c, @core.Critical))
  assert_true(@config.meets_fail_on(c, @core.High))
  assert_false(@config.meets_fail_on(c, @core.Medium))
  let never = @config.ScanConfig::{ ..c, fail_on: @config.Never, }
  assert_false(@config.meets_fail_on(never, @core.Critical))
}

///|
test "shard assignment is deterministic and partitions paths" {
  let c0 = @config.ScanConfig::{
    ..@config.default_config("x"),
    shard_total: 3,
    shard_index: 0,
  }
  let c1 = @config.ScanConfig::{ ..c0, shard_index: 1, }
  let c2 = @config.ScanConfig::{ ..c0, shard_index: 2, }
  let paths = ["a.js", "b.py", "src/c.ts", "deep/dir/e.java", "z.json"]
  for p in paths {
    let hit = [
      @config.in_shard(c0, p),
      @config.in_shard(c1, p),
      @config.in_shard(c2, p),
    ]
    let mut count = 0
    for h in hit {
      if h {
        count += 1
      }
    }
    assert_eq(count, 1)
    // repeat for determinism
    assert_eq(@config.in_shard(c0, p), @config.in_shard(c0, p))
  }
  // single shard accepts everything
  assert_true(@config.in_shard(@config.default_config("x"), "any/path.js"))
}
