///|
/// Maximum number of parse warnings recorded per file. A badly broken file can
/// produce hundreds of error nodes; the cap keeps reports readable and output
/// stable while still satisfying "tolerance must be observable".
const MAX_WARNINGS : Int32 = 20

///|
/// Result of parsing one file. `tree` is `None` only when the grammar could not
/// be loaded or the parser refused to produce a tree — never because the source
/// contains syntax errors.
pub struct ParsedFile {
  path : String
  language : String
  tree : @treesitter.Tree?
  source : Bytes
  warnings : Array[@core.ParseWarning]
}

///|
/// Reused parsers, one per language. `Parser::new` + `set_language` costs more
/// than parsing a small file, and a scan parses many files with the same few
/// grammars. Reuse is safe because `parse` is synchronous and tree-sitter trees
/// own their memory independently of the parser that produced them.
let parser_cache : Map[String, @treesitter.Parser] = Map([])

///|
/// A parser with `spec`'s grammar installed, or `None` when the grammar cannot
/// be loaded (cached failures are not re-attempted; a scan reports per file).
fn parser_for(spec : @lang.LanguageSpec) -> @treesitter.Parser? {
  match parser_cache.get(spec.id) {
    Some(p) => Some(p)
    None => {
      let p = @treesitter.Parser::new()
      let installed = try {
        p.set_language(spec.language())
        true
      } catch {
        _ => false
      }
      if installed {
        parser_cache.set(spec.id, p)
        Some(p)
      } else {
        None
      }
    }
  }
}

///|
/// Parse `text` with the grammar registered for `spec`.
///
/// Syntax errors are reported as `ParseWarning`s and never abort the scan:
/// tree-sitter always returns a tree with `ERROR` / `MISSING` nodes, which we
/// walk explicitly (MVP spec §4.3).
pub fn parse(
  spec : @lang.LanguageSpec,
  text : String,
  path : String,
) -> ParsedFile {
  let source = @utf8.encode(text)
  let parser = match parser_for(spec) {
    Some(p) => p
    None =>
      return {
        path,
        language: spec.id,
        tree: None,
        source,
        warnings: [warning(path, 1, 1, "failed to load grammar '\{spec.id}'")],
      }
  }
  match parser.parse(source) {
    None =>
      {
        path,
        language: spec.id,
        tree: None,
        source,
        warnings: [warning(path, 1, 1, "parser produced no tree for '\{path}'")],
      }
    Some(tree) =>
      {
        path,
        language: spec.id,
        tree: Some(tree),
        source,
        warnings: collect_error_warnings(tree, path),
      }
  }
}

///|
fn warning(
  path : String,
  line : Int32,
  column : Int32,
  message : String,
) -> @core.ParseWarning {
  { path, line, column, message, }
}

///|
/// Collect syntax-error warnings for one tree.
///
/// `has_error()` short-circuits the walk: a file that parsed cleanly cannot
/// produce a warning here (both `ERROR` and `MISSING` nodes make the root
/// report an error), and walking every node of every file just to confirm that
/// is the second-most expensive thing a scan does after matching.
fn collect_error_warnings(
  tree : @treesitter.Tree,
  path : String,
) -> Array[@core.ParseWarning] {
  let out : Array[@core.ParseWarning] = []
  let root = tree.root_node()
  if !root.has_error() {
    return out
  }
  let cursor = tree.walk()
  visit_errors(cursor, path, out)
  if out.length() == 0 {
    out.push(
      warning(
        path,
        root.start_position().row + 1,
        root.start_position().column + 1,
        "syntax error",
      ),
    )
  }
  out
}

///|
fn visit_errors(
  cursor : @treesitter.TreeCursor,
  path : String,
  out : Array[@core.ParseWarning],
) -> Unit {
  if out.length() >= MAX_WARNINGS {
    return
  }
  let node = cursor.node()
  if node.is_error() || node.is_missing() {
    let p = node.start_position()
    let message = if node.is_missing() {
      "missing '\{node.kind()}'"
    } else {
      "syntax error"
    }
    out.push(warning(path, p.row + 1, p.column + 1, message))
    return
  }
  if cursor.goto_first_child() {
    while out.length() < MAX_WARNINGS {
      visit_errors(cursor, path, out)
      if !cursor.goto_next_sibling() {
        break
      }
    }
    let _ = cursor.goto_parent()
  }
}

///|
/// 1-based source location of a node, with byte offset kept for later SARIF use.
pub fn loc_of_node(path : String, node : @treesitter.Node) -> @core.SourceLoc {
  let p = node.start_position()
  {
    path,
    line: p.row + 1,
    column: p.column + 1,
    byte_offset: node.start_byte(),
  }
}

///|
/// Language registration lookup, re-exported so consumers of `parser` (such as
/// `query-engine`) do not need a direct `lang-registry` dependency.
pub fn spec_for_language(id : String) -> @lang.LanguageSpec? {
  @lang.spec_by_id(id)
}

///|
/// Exact source text covered by a node. Returns `""` when the slice is not
/// valid UTF-8 (tree-sitter can produce such nodes in malformed input).
pub fn text_of_node(node : @treesitter.Node, source : Bytes) -> String {
  node.utf8_text(source) catch {
    _ => ""
  }
}

///|
/// Syntax kind of a node (`call_expression`, `identifier`, ...).
pub fn kind_of_node(node : @treesitter.Node) -> String {
  node.kind()
}
