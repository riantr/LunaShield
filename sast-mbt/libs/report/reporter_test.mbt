///|
test "reporter: registry covers every supported format in order" {
  assert_eq(@report.supported_formats(), [
    "console", "json", "junit", "sarif", "html",
  ])
  for f in @report.supported_formats() {
    assert_true(@report.reporter_for(f) is Some(_))
  }
}

///|
test "reporter: unknown format is rejected" {
  assert_true(@report.reporter_for("HTML") is None)
  assert_true(@report.reporter_for("") is None)
  assert_true(@report.reporter_for("JSON") is None)
}

///|
test "reporter: each reporter renders exactly like its function twin" {
  let result = sample_result()
  let pairs : Array[(String, String)] = [
    ("console", @report.render_console(result)),
    ("json", @report.render_json(result)),
    ("junit", @report.render_junit(result)),
    ("sarif", @report.render_sarif(result)),
    ("html", @report.render_html(result)),
  ]
  for pair in pairs {
    match @report.reporter_for(pair.0) {
      Some(rep) => assert_eq(rep.render(result), pair.1)
      None => abort("missing reporter for \{pair.0}")
    }
  }
}

///|
test "reporter: file names are fixed and console has none" {
  let cases : Array[(String, String?)] = [
    ("console", None),
    ("json", Some("findings.json")),
    ("junit", Some("junit.xml")),
    ("sarif", Some("findings.sarif")),
    ("html", Some("findings.html")),
  ]
  for pair in cases {
    match @report.reporter_for(pair.0) {
      Some(rep) => assert_eq(rep.file_name(), pair.1)
      None => abort("missing reporter for \{pair.0}")
    }
  }
}

///|
test "reporter: name matches the registry key for every format" {
  for f in @report.supported_formats() {
    match @report.reporter_for(f) {
      Some(rep) => assert_eq(rep.name(), f)
      None => abort("missing reporter for \{f}")
    }
  }
}
