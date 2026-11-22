///|
/// Result of reading one source file.
pub(all) enum ReadOutcome {
  Text(String)
  Skip(SkipReason)
}

///|
/// Default upper bound for a single source file (8 MiB).
pub const DEFAULT_MAX_BYTES : Int32 = 8 * 1024 * 1024

///|
fn has_nul_byte(bytes : Bytes) -> Bool {
  for b in bytes.iter() {
    if b.to_int() == 0 {
      return true
    }
  }
  false
}

///|
/// Read a file as UTF-8 text, classifying the failure modes that must not abort
/// a scan: oversized files, binaries (NUL byte), and invalid UTF-8.
pub async fn read_source(path : String, max_bytes : Int32) -> ReadOutcome {
  let size = @fs.file_size(path) catch { _ => return Skip(Unreadable) }
  if size > max_bytes.to_int64() {
    return Skip(TooLarge)
  }
  let bytes = @fs.read_file(path).binary() catch {
    _ => return Skip(Unreadable)
  }
  if bytes.length() > max_bytes {
    return Skip(TooLarge)
  }
  if has_nul_byte(bytes) {
    return Skip(Binary)
  }
  let text = @utf8.decode(bytes) catch { _ => return Skip(InvalidUtf8) }
  Text(text)
}

///|
/// SHA-256 of the UTF-8 encoding of `text`, lowercase hex. Used as the cache key
/// and as the content half of the finding fingerprint.
pub fn sha256_hex(text : String) -> String {
  @bithash.hex_encode(@bithash.sha256_raw(@utf8.encode(text)))
}

///|
/// UTF-8 byte length of `text`.
pub fn byte_len(text : String) -> Int32 {
  @utf8.encode(text).length()
}

///|
/// Byte offsets of the first character of each line. `starts[0]` is always 0.
pub fn line_starts(source : Bytes) -> Array[Int32] {
  let starts : Array[Int32] = [0]
  let mut i : Int32 = 0
  let n = source.length()
  while i < n {
    let byte = source.get(i).unwrap()
    if byte.to_int() == 10 {
      starts.push(i + 1)
    }
    i += 1
  }
  starts
}

///|
/// Map a UTF-8 byte offset to a 1-based line/column. Columns are byte-based,
/// matching tree-sitter's `Point.column`, so warnings and findings agree.
pub fn loc_at_offset(
  path : String,
  source : Bytes,
  offset : Int32,
) -> @core.SourceLoc {
  let starts = line_starts(source)
  let mut lo = 0
  let mut hi = starts.length() - 1
  while lo < hi {
    let mid = (lo + hi + 1) / 2
    if starts[mid] <= offset {
      lo = mid
    } else {
      hi = mid - 1
    }
  }
  { path, line: lo + 1, column: offset - starts[lo] + 1, byte_offset: offset, }
}
