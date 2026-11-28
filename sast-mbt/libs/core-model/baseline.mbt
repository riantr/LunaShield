// P2-S5: baseline comparison.
//
// A baseline is the JSON report emitted by an earlier `--format json` scan.
// Comparison is by finding fingerprint (rule id + normalized snippet), not by
// line number, so pure code movement does not show up as a new finding. The
// report DTO is unchanged: baseline state only exists in the in-memory model
// and in SARIF results.

///|
pub fn baseline_state_name(state : BaselineState) -> String {
  match state {
    NotCompared => "not-compared"
    New => "new"
    Unchanged => "unchanged"
  }
}

///|
/// Read the fingerprints from a JSON report. `None` means the input is not a
/// report (or is malformed), which the CLI turns into an argument error.
pub fn parse_baseline_fingerprints(text : String) -> Map[String, Bool]? {
  let json = @json.parse(text) catch { _ => return None }
  guard json is @json.Object(obj) else { return None }
  let findings = match obj.get("findings") {
    Some(@json.Array(arr)) => arr
    _ => return None
  }
  let known : Map[String, Bool] = Map([])
  for entry in findings {
    guard entry is @json.Object(finding) else { continue }
    match finding.get("fingerprint") {
      Some(@json.String(fp)) => known.set(fp, true)
      _ => ()
    }
  }
  Some(known)
}

///|
/// Mark every finding as `New` or `Unchanged`, keeping the full result. Useful
/// for SARIF consumers that want to see both states.
pub fn mark_baseline(
  result : ScanResult,
  known : Map[String, Bool],
) -> ScanResult {
  let findings : Array[Finding] = []
  for f in result.findings {
    let state = match known.get(f.fingerprint) {
      Some(_) => Unchanged
      None => New
    }
    findings.push({ ..f, baseline_state: state, })
  }
  { ..result, findings, }
}

///|
/// Keep only findings absent from the baseline: the `--baseline` CLI gate.
pub fn keep_new(result : ScanResult) -> ScanResult {
  let findings : Array[Finding] = []
  for f in result.findings {
    if f.baseline_state == New {
      findings.push(f)
    }
  }
  { ..result, findings, }
}
