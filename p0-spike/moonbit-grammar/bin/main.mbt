///|
/// Regenerate language_tables from grammar/grammar.json.
/// Run from the spike root: moon run --target native bin
async fn main {
  let grammar_json = @fs.read_file("grammar/grammar.json").text()
  let generated = @generate.generate_from_grammar_json(grammar_json)
  let tables = generated.language.to_compact_base64()
  @fs.write_file("out/language_tables.txt", tables, create_mode=CreateOrTruncate)
  @fs.write_file("out/node-types.json", generated.node_types_json, create_mode=CreateOrTruncate)
  println(
    "generated: name=" + generated.language.name +
    " external_tokens=" + generated.language.external_token_count.to_string() +
    " tables_chars=" + tables.length().to_string(),
  )
}
