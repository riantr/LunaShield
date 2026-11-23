///|
/// A registered language: scan key, file extensions and the grammar entry point.
///
/// `make_language` is stored explicitly because the TypeScript package exports
/// two different functions (`language_typescript` / `language_tsx`) while every
/// other package exports `language()`. Never infer the constructor from the id.
pub struct LanguageSpec {
  id : String
  extensions : Array[String]
  make_language : () -> @treesitter.Language
}

///|
/// Process-wide grammar cache. Materializing a grammar re-reads its tables, and
/// a scan resolves the same grammar once per file, so the handle is kept for the
/// lifetime of the process. Keyed by registration id, which is also the scan key.
let language_cache : Map[String, @treesitter.Language] = Map([])

///|
/// Materialize the grammar for this registration (cached per id).
pub fn LanguageSpec::language(self : LanguageSpec) -> @treesitter.Language {
  match language_cache.get(self.id) {
    Some(l) => l
    None => {
      let l = (self.make_language)()
      language_cache.set(self.id, l)
      l
    }
  }
}

///|
fn spec(
  id : String,
  extensions : Array[String],
  make_language : () -> @treesitter.Language,
) -> LanguageSpec {
  { id, extensions, make_language, }
}

///|
/// Parse the lowercase extension of a POSIX-style path, without the dot.
/// Returns `None` for dotfiles and paths without an extension.
pub fn extension_of(path : String) -> String? {
  let base : String = match path.rev_find("/") {
    Some(i) => path[i + 1:].to_owned()
    None => path
  }
  match base.rev_find(".") {
    Some(0) => None
    Some(i) => Some(base[i + 1:].to_owned().to_lower())
    None => None
  }
}

///|
/// Normalize a user-supplied extension: strip one leading dot, lowercase.
pub fn normalize_extension(ext : String) -> String {
  let trimmed = match ext.strip_prefix(".") {
    Some(rest) => rest.to_owned()
    None => ext
  }
  trimmed.to_lower()
}

///|
/// All six MVP language registrations (see MVP spec §1.3).
pub fn all_language_specs() -> Array[LanguageSpec] {
  [
    spec("javascript", ["js", "jsx", "mjs", "cjs"], () => @tsjs.language()),
    spec("typescript", ["ts"], () => @tsts.language_typescript()),
    spec("tsx", ["tsx"], () => @tsts.language_tsx()),
    spec("python", ["py"], () => @tspy.language()),
    spec("java", ["java"], () => @tsjava.language()),
    spec("json", ["json"], () => @tsjson.language()),
  ]
}

///|
/// All scan keys, in registration order.
pub fn language_ids() -> Array[String] {
  all_language_specs().map(fn(s) { s.id })
}

///|
/// All extensions, in registration order.
pub fn all_extensions() -> Array[String] {
  let out : Array[String] = []
  for s in all_language_specs() {
    for e in s.extensions {
      out.push(e)
    }
  }
  out
}

///|
/// Look up a registration by scan key (`javascript`, `typescript`, ...).
pub fn spec_by_id(id : String) -> LanguageSpec? {
  for s in all_language_specs() {
    if s.id == id {
      return Some(s)
    }
  }
  None
}

///|
/// Look up a registration by extension. Accepts `js` or `.js`, any case.
pub fn spec_by_extension(ext : String) -> LanguageSpec? {
  let want = normalize_extension(ext)
  for s in all_language_specs() {
    for e in s.extensions {
      if e == want {
        return Some(s)
      }
    }
  }
  None
}

///|
/// Look up a registration by file path using its extension.
pub fn spec_by_path(path : String) -> LanguageSpec? {
  match extension_of(path) {
    Some(ext) => spec_by_extension(ext)
    None => None
  }
}
