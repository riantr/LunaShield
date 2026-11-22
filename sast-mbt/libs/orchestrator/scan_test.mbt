///|
/// The taint manifest must be found next to rules.json regardless of which
/// path flavour the CLI received. A silent miss would downgrade every verdict
/// to NotApplicable and make `--taint` look enabled while doing nothing.
test "taint manifest path: POSIX, Windows and bare file forms" {
  assert_eq(@orchestrator.taint_file("pack/rules.json"), "pack/taint.json")
  assert_eq(@orchestrator.taint_file("rules.json"), "taint.json")
  assert_eq(
    @orchestrator.taint_file("D:\\pack\\rules.json"),
    "D:\\pack\\taint.json",
  )
  assert_eq(@orchestrator.taint_file("D:\\pack"), "D:\\pack\\taint.json")
  assert_eq(@orchestrator.taint_file("pack"), "pack/taint.json")
}
