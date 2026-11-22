// Finalization stage: fingerprinting, deterministic ordering, deduplication and
// in-source suppression. No IO, no config: the caller decides the fail-on gate.

///|
/// Collapse every run of whitespace to a single space and drop leading/trailing
/// whitespace. Keeps fingerprints stable across formatting-only edits.
pub fn normalize_snippet(s : String) -> String {
  let parts : Array[String] = []
  let mut pending_space = false
  for c in s {
    let is_space = c == ' ' || c == '\t' || c == '\n' || c == '\r'
    if is_space {
      pending_space = true
    } else {
      if pending_space && parts.length() > 0 {
        parts.push(" ")
      }
      pending_space = false
      parts.push("\{c}")
    }
  }
  parts.join("")
}

///|
/// `sha256(rule_id + "|" + normalize(snippet))`, lowercase hex.
///
/// Byte-compatible with the P0 baseline: for `JS001` + `eval` this yields
/// `cad6a9d402bd4d6c926a60f7d06d046c4fdf4b613dab5be32c2189e45cd3da31`.
pub fn make_fingerprint(rule_id : String, snippet : String) -> String {
  let input = rule_id + "|" + normalize_snippet(snippet)
  @bithash.hex_encode(@bithash.sha256_raw(@utf8.encode(input)))
}

///|
/// An inline suppression directive (`// sast-ignore` / `// sast-ignore-next-line`).
#derive(Debug, Eq)
pub(all) struct Suppression {
  line : Int32
  rule_ids : Array[String]
}

///|
fn parse_rule_ids(rest : String) -> Array[String] {
  let ids : Array[String] = []
  let after_colon = match rest.find(":") {
    Some(i) => rest[i + 1:].to_owned()
    None => return ids
  }
  for raw in after_colon.split(",") {
    let id = raw.trim().to_owned()
    if id.length() > 0 {
      ids.push(id)
    }
  }
  ids
}

///|
/// Extract suppression directives from source text.
///
/// `// sast-ignore` suppresses findings on its own line,
/// `// sast-ignore-next-line` on the following line, and an optional
/// `: JS001,JS003` suffix limits the suppression to those rules.
pub fn parse_suppressions(text : String) -> Array[Suppression] {
  let out : Array[Suppression] = []
  let mut line_no : Int32 = 0
  for raw in text.split("\n") {
    line_no += 1
    let line = raw.to_owned()
    let at = match line.find("sast-ignore") {
      Some(i) => i
      None => continue
    }
    let rest = line[at:].to_owned()
    let next_directive = "sast-ignore-next-line"
    let same_directive = "sast-ignore"
    let (target, tail) = if rest.has_prefix(next_directive) {
      (line_no + 1, rest[next_directive.length():].to_owned())
    } else if rest.has_prefix(same_directive) {
      (line_no, rest[same_directive.length():].to_owned())
    } else {
      continue
    }
    out.push({ line: target, rule_ids: parse_rule_ids(tail), })
  }
  out
}

///|
pub fn is_hit_suppressed(
  sups : Array[Suppression],
  line : Int32,
  rule_id : String,
) -> Bool {
  for s in sups {
    if s.line == line {
      if s.rule_ids.length() == 0 {
        return true
      }
      for id in s.rule_ids {
        if id == rule_id {
          return true
        }
      }
    }
  }
  false
}

///|
fn cmp_str(a : String, b : String) -> Int32 {
  a[:].lexical_compare(b[:]).to_int()
}

///|
fn cmp_i32(a : Int32, b : Int32) -> Int32 {
  if a < b {
    -1
  } else if a > b {
    1
  } else {
    0
  }
}

///|
/// Total order over findings: path, line, column, rule_id, fingerprint.
fn compare_findings(a : @core.Finding, b : @core.Finding) -> Int32 {
  let by_path = cmp_str(a.primary.path, b.primary.path)
  if by_path != 0 {
    return by_path
  }
  let by_line = cmp_i32(a.primary.line, b.primary.line)
  if by_line != 0 {
    return by_line
  }
  let by_col = cmp_i32(a.primary.column, b.primary.column)
  if by_col != 0 {
    return by_col
  }
  let by_rule = cmp_str(a.rule_id, b.rule_id)
  if by_rule != 0 {
    return by_rule
  }
  cmp_str(a.fingerprint, b.fingerprint)
}

///|
/// Confidence implied by the optional taint verdict (P2-S4b).
///
/// - `NotApplicable` (taint off / not configured / rule not a sink) and
///   `Confirmed` keep the AST baseline `High`.
/// - `Sanitized` / `NoSource` are refuted flows, downgraded to `Low`.
///
/// Keeping `NotApplicable` at `High` is the safety invariant: before taint is
/// wired into the scan every hit is `NotApplicable`, so output is byte-for-byte
/// identical to the pre-taint analyzer.
pub fn confidence_from_taint(v : @core.TaintVerdict) -> @core.Confidence {
  match v {
    NotApplicable => @core.High
    Confirmed => @core.High
    Sanitized => @core.Low
    NoSource => @core.Low
  }
}

///|
/// A verdict that a strict-mode scan prunes. `NotApplicable` is never weak:
/// absence of taint evidence must not remove a finding.
pub fn is_weak_verdict(v : @core.TaintVerdict) -> Bool {
  match v {
    Sanitized => true
    NoSource => true
    _ => false
  }
}

///|
/// Drop hits refuted by taint, for the `--taint strict` gate. Provided here as
/// a pure function so the pipeline decides *whether* to apply it while scoring
/// owns *what* counts as weak. With all hits `NotApplicable` this is identity.
pub fn prune_by_taint(hits : Array[@core.RawHit]) -> Array[@core.RawHit] {
  let kept : Array[@core.RawHit] = []
  for h in hits {
    if !is_weak_verdict(h.taint) {
      kept.push(h)
    }
  }
  kept
}

///|
/// Convert one raw hit into a finding (fingerprint and confidence computed here).
pub fn finding_from_hit(h : @core.RawHit) -> @core.Finding {
  {
    rule_id: h.rule_id,
    severity: h.severity,
    confidence: confidence_from_taint(h.taint),
    cwe: h.cwe,
    owasp: h.owasp,
    primary: h.primary,
    related: [],
    message: h.message,
    snippet: h.snippet,
    fingerprint: make_fingerprint(h.rule_id, h.snippet),
  }
}

///|
/// Sort findings into the canonical total order and drop duplicates.
///
/// Dedupe is per `(path, fingerprint)`: the same snippet in two files is two
/// defects, repeated matches inside one file collapse to one. `raw_hits` is
/// carried through so reports can show pre-dedupe volume.
pub fn finalize_findings(
  findings : Array[@core.Finding],
  raw_hits : Int32,
) -> @core.ScanResult {
  findings.mut_view().sort_by(compare_findings)
  let seen : Map[String, Bool] = Map([])
  let unique : Array[@core.Finding] = []
  for f in findings {
    let key = f.primary.path + "\u{0}" + f.fingerprint
    match seen.get(key) {
      Some(_) => ()
      None => {
        seen.set(key, true)
        unique.push(f)
      }
    }
  }
  {
    findings: unique,
    warnings: [],
    skipped_files: [],
    stats: {
      files_scanned: 0,
      files_skipped: 0,
      bytes_scanned: 0,
      raw_hits,
      duration_ms: 0,
    },
  }
}

///|
/// Convert raw hits into a `ScanResult`: apply suppressions, compute
/// fingerprints, then sort and dedupe.
pub fn finalize_with(
  hits : Array[@core.RawHit],
  suppressions : Array[Suppression],
) -> @core.ScanResult {
  let findings : Array[@core.Finding] = []
  for h in hits {
    if !is_hit_suppressed(suppressions, h.primary.line, h.rule_id) {
      findings.push(finding_from_hit(h))
    }
  }
  finalize_findings(findings, hits.length().to_int())
}

///|
/// `finalize_with` without suppressions.
pub fn finalize(hits : Array[@core.RawHit]) -> @core.ScanResult {
  finalize_with(hits, [])
}
