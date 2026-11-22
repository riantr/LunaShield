// Reusable end-to-end pipeline pieces for integration tests.
//
// This lives in a library file (not the test file) on purpose: it keeps the
// package imports genuinely used by library code and gives later milestones a
// place to grow a mini orchestrator without touching the assertions.

///|
/// P0 baseline: sha256("JS001|eval"), reproduced byte for byte.
pub const P0_FINGERPRINT : String = "cad6a9d402bd4d6c926a60f7d06d046c4fdf4b613dab5be32c2189e45cd3da31"

///|
/// Load the shipped official rule pack from the repository tree.
pub async fn official_rules() -> Array[@rule.Rule] {
  let text = @fs.read_file("../../rulepacks/official/rules.json").text()
  @rule.parse_rules(@json.parse(text)) catch {
    e => abort("official rules failed to parse: \{e}")
  }
}

///|
/// Parse one file with the grammar registered for its extension and run every
/// applicable rule. Returns the finalized result (fingerprinted, sorted, deduped).
pub async fn scan_file(path : String) -> @core.ScanResult {
  let rules = official_rules()
  let spec = match @lang.spec_by_path(path) {
    Some(s) => s
    None => abort("no language registration for \{path}")
  }
  let text = @fs.read_file(path).text()
  let parsed = @parser.parse(spec, text, path)
  let run = @query-engine.run_rules(parsed, rules)
  if run.failures.length() > 0 {
    abort(
      "rule failures: \{run.failures[0].rule_id}: \{run.failures[0].message}",
    )
  }
  let suppressions = @scoring.parse_suppressions(text)
  @scoring.finalize_with(run.hits, suppressions)
}

///|
/// Canonical one-line-per-finding rendering used to assert determinism.
pub fn render(result : @core.ScanResult) -> String {
  let parts : Array[String] = []
  for f in result.findings {
    parts.push(
      "\{f.primary.path}:\{f.primary.line}:\{f.primary.column}|\{f.rule_id}|\{f.snippet}|\{f.fingerprint}",
    )
  }
  parts.join("\n")
}
