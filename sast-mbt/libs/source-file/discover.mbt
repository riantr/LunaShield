///|
/// Why a candidate file was not scanned. Reported in `ScanResult.skipped_files`
/// so users can tell "ignored by config" from "could not be read".
#derive(Debug, Eq)
pub(all) enum SkipReason {
  Ignored
  UnregisteredLanguage
  Binary
  InvalidUtf8
  TooLarge
  Unreadable
}

///|
/// Stable lowercase name used in reports.
pub fn skip_reason_name(r : SkipReason) -> String {
  match r {
    Ignored => "ignored"
    UnregisteredLanguage => "unregistered-language"
    Binary => "binary"
    InvalidUtf8 => "invalid-utf8"
    TooLarge => "too-large"
    Unreadable => "unreadable"
  }
}

///|
/// A file that was discovered but deliberately not scanned.
#derive(Debug, Eq)
pub(all) struct SkippedFile {
  path : String
  reason : SkipReason
}

///|
/// Deterministic discovery output. `files` is sorted and POSIX-separated.
#derive(Debug, Eq)
pub(all) struct DiscoverResult {
  files : Array[String]
  skipped : Array[SkippedFile]
}

///|
/// Directories never descended into. Kept deliberately short: build-output
/// directories other than `_build` may legitimately contain sources.
fn excluded_dirs() -> Array[String] {
  [".git", ".hg", ".svn", "_build", ".mooncakes", "node_modules", "target"]
}

///|
fn to_posix(p : String) -> String {
  p.replace(old="\\", new="/")
}

///|
fn basename_of(p : String) -> String {
  let s = to_posix(p)
  match s.rev_find("/") {
    Some(i) => s[i + 1:].to_owned()
    None => s
  }
}

///|
fn normalize_root(root : String) -> String {
  let p = to_posix(root)
  if p == "" {
    return "."
  }
  let mut s = p
  while s.length() > 1 {
    match s.rev_find("/") {
      Some(i) => if i == s.length() - 1 { s = s[:i].to_owned() } else { break }
      None => break
    }
  }
  s
}

///|
fn join_path(dir : String, name : String) -> String {
  if dir == "" {
    return name
  }
  if dir.rev_find("/") == Some(dir.length() - 1) {
    return dir + name
  }
  dir + "/" + name
}

///|
fn is_excluded_dir(name : String) -> Bool {
  for d in excluded_dirs() {
    if d == name {
      return true
    }
  }
  false
}

///|
fn has_extension(extensions : Array[String], ext : String) -> Bool {
  for e in extensions {
    if e == ext {
      return true
    }
  }
  false
}

///|
/// Lowercase extension of a path without the dot. Implemented locally so
/// `source-file` stays free of grammar dependencies.
fn extension_of(path : String) -> String? {
  let base = basename_of(path)
  match base.rev_find(".") {
    Some(0) => None
    Some(i) => Some(base[i + 1:].to_owned().to_lower())
    None => None
  }
}

///|
/// Mutable accumulator passed through the recursive walk.
priv struct Collector {
  files : Array[String]
  skipped : Array[SkippedFile]
  matcher : @bitignore.Matcher
  extensions : Array[String]
}

///|
fn Collector::consider_file(self : Collector, rel : String) -> Unit {
  if self.matcher.is_ignored(rel, false) {
    self.skipped.push({ path: rel, reason: Ignored, })
    return
  }
  match extension_of(rel) {
    Some(ext) =>
      if has_extension(self.extensions, ext) {
        self.files.push(rel)
      } else {
        self.skipped.push({ path: rel, reason: UnregisteredLanguage, })
      }
    None => self.skipped.push({ path: rel, reason: UnregisteredLanguage, })
  }
}

///|
/// Depth-first traversal.
///
/// `@fs.walk` is deliberately NOT used: we need per-directory read failures
/// (`allow_failure` would swallow them) and a complete listing before sorting.
/// `readdir(sort?=true)` is accepted by the API but does not actually order the
/// entries in this toolchain (observed: `lib, ignored, main.js, Makefile, ...`),
/// so ordering is established afterwards by `merge_sort_by`.
async fn Collector::walk_dir(
  self : Collector,
  dir : String,
  rel_dir : String,
) -> Unit {
  let entries = @fs.readdir(dir, sort=true) catch {
    _ => {
      self.skipped.push({ path: rel_dir, reason: Unreadable, })
      return
    }
  }
  for name in entries {
    let full = join_path(dir, name)
    let rel = if rel_dir == "" { name } else { rel_dir + "/" + name }
    let kind = @fs.kind(full) catch { _ => @fs.FileKind::Unknown }
    match kind {
      @fs.FileKind::Directory =>
        if !is_excluded_dir(name) {
          self.walk_dir(full, rel)
        }
      @fs.FileKind::Regular => self.consider_file(rel)
      @fs.FileKind::SymLink => self.consider_file(rel)
      _ => ()
    }
  }
}

///|
/// Load root-level ignore files (`.gitignore`, `.sastignore`, ...) into one
/// matcher. Missing files are ignored; nested ignore files are a P2 item.
async fn build_matcher(
  scan_root : String,
  ignore_files : Array[String],
) -> @bitignore.Matcher {
  let matcher = @bitignore.Matcher::new()
  for name in ignore_files {
    let p = join_path(scan_root, name)
    let exists = @fs.exists(p) catch { _ => false }
    if exists {
      let text = @fs.read_file(p).text() catch { _ => "" }
      if text.length() > 0 {
        matcher.add_rules("", text)
      }
    }
  }
  matcher
}

///|
/// Discover every regular file under `root` whose extension is registered,
/// honouring root-level ignore files. Paths are relative and POSIX-separated;
/// results are sorted so two runs on the same tree produce identical output.
pub async fn discover(
  root : String,
  extensions : Array[String],
  ignore_files : Array[String],
  extra_patterns? : Array[String],
) -> DiscoverResult {
  let scan_root = normalize_root(root)
  let matcher = build_matcher(scan_root, ignore_files)
  match extra_patterns {
    Some(patterns) =>
      if patterns.length() > 0 {
        matcher.add_rules("", patterns.join("\n"))
      }
    None => ()
  }
  let collector : Collector = { files: [], skipped: [], matcher, extensions, }
  collector.walk_dir(scan_root, "")
  {
    files: sorted_strings(collector.files),
    skipped: sorted_skipped(collector.skipped),
  }
}

///|
/// Copy an array into a fresh allocation.
fn[T] copy_of(xs : Array[T]) -> Array[T] {
  let out : Array[T] = []
  for x in xs {
    out.push(x)
  }
  out
}

///|
fn int_min(a : Int32, b : Int32) -> Int32 {
  if a < b {
    a
  } else {
    b
  }
}

///|
/// Append `src[start:mid]` and `src[mid:end]` to `dst` in comparator order.
fn[T] merge_range(
  src : Array[T],
  start : Int32,
  mid : Int32,
  end : Int32,
  dst : Array[T],
  cmp : (T, T) -> Int32,
) -> Unit {
  let mut i = start
  let mut j = mid
  while i < mid && j < end {
    if cmp(src[i], src[j]) <= 0 {
      dst.push(src[i])
      i += 1
    } else {
      dst.push(src[j])
      j += 1
    }
  }
  while i < mid {
    dst.push(src[i])
    i += 1
  }
  while j < end {
    dst.push(src[j])
    j += 1
  }
}

///|
/// Bottom-up merge sort over a freshly allocated array, ordered by `cmp`.
///
/// A hand-written merge is used because the ordering we need is *lexicographic*
/// while the stdlib `Compare for String` is **shortlex** (length first, then
/// code units) — `"main.js".compare("binary.js")` returns `-1`. Sorting paths by
/// shortlex looks arbitrary in reports, so `compare_strings` calls
/// `StringView::lexical_compare` instead. A push-only merge keeps the whole
/// operation free of in-place mutation.
fn[T] merge_sort_by(xs : Array[T], cmp : (T, T) -> Int32) -> Array[T] {
  let n = xs.length()
  if n <= 1 {
    return copy_of(xs)
  }
  let mut width = 1
  let mut src = copy_of(xs)
  while width < n {
    let dst : Array[T] = []
    let mut i = 0
    while i < n {
      let mid = int_min(i + width, n)
      let end = int_min(i + 2 * width, n)
      merge_range(src, i, mid, end, dst, cmp)
      i += 2 * width
    }
    src = dst
    width = width * 2
  }
  src
}

///|
/// Lexicographic (code-unit) ordering, unlike `String::compare` (shortlex).
fn compare_strings(a : String, b : String) -> Int32 {
  a[:].lexical_compare(b[:]).to_int()
}

///|
fn sorted_strings(xs : Array[String]) -> Array[String] {
  merge_sort_by(xs, compare_strings)
}

///|
fn sorted_skipped(xs : Array[SkippedFile]) -> Array[SkippedFile] {
  merge_sort_by(xs, fn(a, b) { compare_strings(a.path, b.path) })
}
