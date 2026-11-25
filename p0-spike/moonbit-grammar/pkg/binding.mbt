// MoonBit grammar binding: parse tables + the ported external scanner.

///|
let language_cache : Ref[@treesitter.Language?] = Ref(None)

///|
pub fn language() -> @treesitter.Language {
  match language_cache.val {
    Some(l) => l
    None => {
      let raw = @language.Language::from_compact_base64(language_tables) catch {
        e => abort(Show::to_string(e))
      }
      let l = @treesitter.Language::new(raw, external_scanner=moonbit_scanner)
      language_cache.val = Some(l)
      l
    }
  }
}
