// P2-S2: reporter abstraction.
//
// The four MVP/P2 renderers keep their byte-for-byte output; this layer only adds
// discoverability (`reporter_for`) and a stable extension point. DTOs are
// untouched on purpose — cram snapshots are the regression guard.

///|
/// A report renderer. `file_name` is `None` for the human summary that always
/// goes to stdout.
pub(open) trait Reporter {
  fn name(Self) -> String
  fn render(Self, @core.ScanResult) -> String
  fn file_name(Self) -> String?
}

///|
pub struct ConsoleReporter {}

///|
pub struct JsonReporter {}

///|
pub struct JunitReporter {}

///|
pub struct SarifReporter {}

///|
pub impl Reporter for ConsoleReporter with fn name(_self) {
  "console"
}

///|
pub impl Reporter for ConsoleReporter with fn render(_self, result) {
  render_console(result)
}

///|
pub impl Reporter for ConsoleReporter with fn file_name(_self) {
  None
}

///|
pub impl Reporter for JsonReporter with fn name(_self) {
  "json"
}

///|
pub impl Reporter for JsonReporter with fn render(_self, result) {
  render_json(result)
}

///|
pub impl Reporter for JsonReporter with fn file_name(_self) {
  Some("findings.json")
}

///|
pub impl Reporter for JunitReporter with fn name(_self) {
  "junit"
}

///|
pub impl Reporter for JunitReporter with fn render(_self, result) {
  render_junit(result)
}

///|
pub impl Reporter for JunitReporter with fn file_name(_self) {
  Some("junit.xml")
}

///|
pub impl Reporter for SarifReporter with fn name(_self) {
  "sarif"
}

///|
pub impl Reporter for SarifReporter with fn render(_self, result) {
  render_sarif(result)
}

///|
pub impl Reporter for SarifReporter with fn file_name(_self) {
  Some("findings.sarif")
}

///|
/// Canonical emission order. `apps/scan` iterates this (not the user's CSV order)
/// so mixed `--format` invocations stay deterministic.
pub fn supported_formats() -> Array[String] {
  ["console", "json", "junit", "sarif"]
}

///|
/// Look up a reporter by `--format` value.
pub fn reporter_for(format : String) -> &Reporter? {
  match format {
    "console" => Some(ConsoleReporter::{ })
    "json" => Some(JsonReporter::{ })
    "junit" => Some(JunitReporter::{ })
    "sarif" => Some(SarifReporter::{ })
    _ => None
  }
}
