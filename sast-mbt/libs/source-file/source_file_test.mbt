///|
let scan_exts : Array[String] = ["js", "mjs", "ts", "tsx", "py", "java", "json"]

///|
let ignore_files : Array[String] = [".gitignore", ".sastignore"]

///|
fn skip_reason_for(
  res : @source-file.DiscoverResult,
  path : String,
) -> @source-file.SkipReason? {
  for s in res.skipped {
    if s.path == path {
      return Some(s.reason)
    }
  }
  None
}

///|
async test "discover: fixture file set is exact and deterministic" {
  let res = @source-file.discover("testdata", scan_exts, ignore_files)
  assert_eq(res.files, [
    "binary.js", "lib/helper.js", "lib/nested.ts", "main.js", "util.mjs",
  ])
  // A second run must produce byte-identical ordering.
  let again = @source-file.discover("testdata", scan_exts, ignore_files)
  assert_eq(again.files, res.files)
}

///|
async test "discover: .gitignore patterns and ignored directories" {
  let res = @source-file.discover("testdata", scan_exts, ignore_files)
  assert_eq(
    skip_reason_for(res, "secret.js"),
    Some(@source-file.SkipReason::Ignored),
  )
  assert_eq(
    skip_reason_for(res, "debug.log"),
    Some(@source-file.SkipReason::Ignored),
  )
  assert_eq(
    skip_reason_for(res, "ignored/skip.js"),
    Some(@source-file.SkipReason::Ignored),
  )
  assert_true(!res.files.contains("ignored/skip.js"))
}

///|
async test "discover: extensionless and unknown extensions are skipped" {
  let res = @source-file.discover("testdata", scan_exts, ignore_files)
  assert_eq(
    skip_reason_for(res, "Makefile"),
    Some(@source-file.SkipReason::UnregisteredLanguage),
  )
  assert_eq(
    skip_reason_for(res, "notes.txt"),
    Some(@source-file.SkipReason::UnregisteredLanguage),
  )
}

///|
async test "discover: subdirectories are walked and recurse one level" {
  let res = @source-file.discover("testdata/lib", ["js", "ts"], [])
  assert_eq(res.files, ["helper.js", "nested.ts"])
}

///|
async test "read: text files decode, binaries and oversize files are classified" {
  match
    @source-file.read_source("testdata/main.js", @source-file.DEFAULT_MAX_BYTES) {
    @source-file.Text(text) => assert_eq(text, "const x = 1;\n")
    _ => abort("expected text")
  }
  match
    @source-file.read_source(
      "testdata/binary.js",
      @source-file.DEFAULT_MAX_BYTES,
    ) {
    @source-file.Skip(reason) =>
      assert_eq(reason, @source-file.SkipReason::Binary)
    _ => abort("expected binary skip")
  }
  match @source-file.read_source("testdata/util.mjs", 4) {
    @source-file.Skip(reason) =>
      assert_eq(reason, @source-file.SkipReason::TooLarge)
    _ => abort("expected too-large skip")
  }
  match @source-file.read_source("testdata/does-not-exist.js", 1024) {
    @source-file.Skip(reason) =>
      assert_eq(reason, @source-file.SkipReason::Unreadable)
    _ => abort("expected unreadable skip")
  }
}

///|
test "hash: sha256 matches NIST vector and ignores platform newlines" {
  assert_eq(
    @source-file.sha256_hex("abc"),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  )
  assert_true(@source-file.sha256_hex("abc") != @source-file.sha256_hex("abd"))
  assert_eq(@source-file.byte_len("abc"), 3)
  assert_eq(@source-file.byte_len("中文"), 6)
}

///|
test "loc: byte offset maps to 1-based line and column" {
  let source = @utf8.encode("a\nbb\nccc\n")
  assert_eq(@source-file.line_starts(source), [0, 2, 5, 9])
  let first = @source-file.loc_at_offset("f.js", source, 0)
  assert_eq(first.line, 1)
  assert_eq(first.column, 1)
  let second = @source-file.loc_at_offset("f.js", source, 2)
  assert_eq(second.line, 2)
  assert_eq(second.column, 1)
  let mid = @source-file.loc_at_offset("f.js", source, 4)
  assert_eq(mid.line, 2)
  assert_eq(mid.column, 3)
  let last = @source-file.loc_at_offset("f.js", source, 8)
  assert_eq(last.line, 3)
  assert_eq(last.column, 4)
  assert_eq(last.byte_offset, 8)
}

///|
async test "read_source: missing and oversized files are Skip, not errors" {
  let missing = @source-file.read_source(".tmp-no-such-file.js", 1024) catch {
    _ => abort("read_source must not raise")
  }
  assert_true(missing is @source-file.Skip(_))
  match missing {
    @source-file.Skip(reason) => assert_eq(reason, @source-file.Unreadable)
    @source-file.Text(_) => abort("expected a skip")
  }
  // A 4-byte file read with a 2-byte cap is TooLarge.
  let dir = ".tmp-read-limit"
  let _ = @fs.rmdir(dir, recursive=true, allow_missing=true) catch { _ => () }
  @fs.mkdir(dir, recursive=true, allow_exist=true)
  @fs.write_file(dir + "/big.js", "eval(1)\n")
  let big = @source-file.read_source(dir + "/big.js", 2) catch {
    _ => abort("read_source must not raise")
  }
  match big {
    @source-file.Skip(reason) => assert_eq(reason, @source-file.TooLarge)
    @source-file.Text(_) => abort("expected TooLarge")
  }
  let _ = @fs.rmdir(dir, recursive=true, allow_missing=true) catch { _ => () }
}

///|
test "skip reasons: every reason has a stable name" {
  assert_eq(@source-file.skip_reason_name(@source-file.Ignored), "ignored")
  assert_eq(@source-file.skip_reason_name(@source-file.Binary), "binary")
  assert_eq(@source-file.skip_reason_name(@source-file.TooLarge), "too-large")
  assert_eq(
    @source-file.skip_reason_name(@source-file.Unreadable),
    "unreadable",
  )
  assert_eq(
    @source-file.skip_reason_name(@source-file.InvalidUtf8),
    "invalid-utf8",
  )
}

///|
async test "discover: extra ignore patterns are honoured" {
  let dir = ".tmp-discover-extra"
  let _ = @fs.rmdir(dir, recursive=true, allow_missing=true) catch { _ => () }
  @fs.mkdir(dir, recursive=true, allow_exist=true)
  @fs.write_file(dir + "/keep.js", "eval(1)\n")
  @fs.write_file(dir + "/drop.tmp.js", "eval(1)\n")
  let found = @source-file.discover(dir, ["js"], [], extra_patterns=["*.tmp.js"]) catch {
    _ => abort("discover must not raise")
  }
  assert_eq(found.files, ["keep.js"])
  let _ = @fs.rmdir(dir, recursive=true, allow_missing=true) catch { _ => () }
}
