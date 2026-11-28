///|
fn stmt(
  id : Int32,
  kind : @dataflow.StmtKind,
  vars : Array[String],
) -> @dataflow.Stmt {
  @dataflow.Stmt::{ id, start: id * 10, end: id * 10 + 5, kind, vars, }
}

///|
test "set helpers: union is sorted and unique, difference removes names" {
  let merged = @dataflow.union(["b", "a", "b"], ["c", "a"])
  assert_eq(merged, ["a", "b", "c"])
  assert_eq(@dataflow.difference(merged, ["b"]), ["a", "c"])
  assert_eq(@dataflow.difference(merged, ["x"]), merged)
}

///|
test "CFG: sequential edges plus explicit branch and backedge" {
  let stmts = [
    stmt(0, @dataflow.Plain, []),
    stmt(1, @dataflow.Source, ["x"]),
    stmt(2, @dataflow.Sanitizer, ["x"]),
    stmt(3, @dataflow.Sink, []),
  ]
  let cfg = @dataflow.build_cfg(stmts, [(1, 3), (3, 1)])
  assert_eq(cfg.blocks.length(), 4)
  assert_eq(@dataflow.successors(cfg, 0), [1])
  assert_eq(@dataflow.successors(cfg, 1), [2, 3])
  assert_eq(@dataflow.successors(cfg, 3), [1])
  assert_eq(@dataflow.reachable(cfg), [0, 1, 2, 3])
}

///|
test "dataflow: source reaches sink until a sanitizer removes it" {
  let stmts = [
    stmt(0, @dataflow.Plain, []),
    stmt(1, @dataflow.Source, ["x"]),
    stmt(2, @dataflow.Sanitizer, ["x"]),
    stmt(3, @dataflow.Sink, []),
  ]
  let states = @dataflow.solve(@dataflow.build_cfg(stmts, []))
  assert_eq(states.get(1), Some([]))
  assert_eq(states.get(2), Some(["x"]))
  assert_eq(states.get(3), Some([]))
}

///|
test "dataflow: a branch bypassing the sanitizer keeps the taint (may-analysis)" {
  let stmts = [
    stmt(0, @dataflow.Plain, []),
    stmt(1, @dataflow.Source, ["x"]),
    stmt(2, @dataflow.Sanitizer, ["x"]),
    stmt(3, @dataflow.Sink, []),
  ]
  let states = @dataflow.solve(@dataflow.build_cfg(stmts, [(1, 3)]))
  assert_eq(states.get(2), Some(["x"]))
  assert_eq(states.get(3), Some(["x"]))
}

///|
test "dataflow: loops converge and propagate names to the exit" {
  let stmts = [
    stmt(0, @dataflow.Plain, []),
    stmt(1, @dataflow.Source, ["y"]),
    stmt(2, @dataflow.Sink, []),
  ]
  let cfg = @dataflow.build_cfg(stmts, [(2, 1)])
  let states = @dataflow.solve(cfg)
  assert_eq(states.get(1), Some(["y"]))
  assert_eq(states.get(2), Some(["y"]))
  assert_eq(@dataflow.reachable(cfg), [0, 1, 2])
}

///|
test "dataflow: empty CFG has empty state and no reachable blocks" {
  let cfg = @dataflow.build_cfg([], [])
  assert_eq(@dataflow.solve(cfg).get(0), None)
  assert_eq(@dataflow.reachable(cfg), [])
}

///|
test "transfer: only Source and Sanitizer change the lattice" {
  let s = stmt(0, @dataflow.Plain, ["ignored"])
  assert_eq(@dataflow.transfer(s, ["x"]), ["x"])
  let source = stmt(1, @dataflow.Source, ["x", "y"])
  assert_eq(@dataflow.transfer(source, ["a"]), ["a", "x", "y"])
  let san = stmt(2, @dataflow.Sanitizer, ["x"])
  assert_eq(@dataflow.transfer(san, ["x", "y"]), ["y"])
}
