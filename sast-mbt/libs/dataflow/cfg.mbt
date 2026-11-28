// P2-S4c: a small, deterministic CFG + worklist dataflow engine.
//
// The graph is explicit: callers turn a function body into ordered statements
// and supply any non-sequential edges (branches, loop backedges). The engine
// itself never looks at source text, so the fixed point is reproducible and
// easy to test independently of any grammar.
//
// The lattice is a set of tainted variable names. `Source` adds names,
// `Sanitizer` removes them, everything else is identity. Sets are merged by
// union, which is a monotone may-analysis: a name reaches a block if *any*
// path carries it. Loops converge because the state can only grow or lose
// names through a sanitizer, and every transfer is monotone w.r.t. union.

///|
#derive(Debug, Eq)
pub(all) enum StmtKind {
  Plain
  Source
  Sanitizer
  Sink
}

///|
#derive(Debug, Eq)
pub(all) struct Stmt {
  /// Stable block id, unique within one CFG.
  id : Int32
  /// Source byte range; carried through so callers can map blocks back to AST.
  start : Int32
  end : Int32
  kind : StmtKind
  /// Variable names introduced (Source) or cleared (Sanitizer).
  vars : Array[String]
}

///|
#derive(Debug, Eq)
pub(all) struct CFG {
  /// Statements in source order.
  blocks : Array[Stmt]
  /// Edge list `(from, to)`. Sequential edges are added by `build_cfg`.
  edges : Array[(Int32, Int32)]
  entry : Int32
}

///|
fn cmp_str(a : String, b : String) -> Int32 {
  a[:].lexical_compare(b[:]).to_int()
}

///|
fn same_array(a : Array[String], b : Array[String]) -> Bool {
  if a.length() != b.length() {
    return false
  }
  let mut i = 0
  while i < a.length() {
    if a[i] != b[i] {
      return false
    }
    i += 1
  }
  true
}

///|
fn sorted_unique(names : Array[String]) -> Array[String] {
  let seen : Map[String, Bool] = Map([])
  for name in names {
    seen.set(name, true)
  }
  let out : Array[String] = []
  for (name, _) in seen.iter() {
    out.push(name)
  }
  out.mut_view().sort_by(fn(a, b) { cmp_str(a, b) })
  out
}

///|
pub fn union(a : Array[String], b : Array[String]) -> Array[String] {
  let out : Array[String] = []
  for name in a {
    out.push(name)
  }
  for name in b {
    out.push(name)
  }
  sorted_unique(out)
}

///|
pub fn difference(a : Array[String], b : Array[String]) -> Array[String] {
  let removed : Map[String, Bool] = Map([])
  for name in b {
    removed.set(name, true)
  }
  let out : Array[String] = []
  for name in a {
    match removed.get(name) {
      Some(_) => ()
      None => out.push(name)
    }
  }
  sorted_unique(out)
}

///|
/// Build a CFG from ordered statements plus caller-supplied extra edges.
/// Sequential edges `i -> i+1` are implicit; duplicates are harmless because
/// worklist successors are deduplicated.
pub fn build_cfg(
  stmts : Array[Stmt],
  extra_edges : Array[(Int32, Int32)],
) -> CFG {
  let edges : Array[(Int32, Int32)] = []
  let mut i = 0
  while i + 1 < stmts.length() {
    edges.push((stmts[i].id, stmts[i + 1].id))
    i += 1
  }
  for edge in extra_edges {
    edges.push(edge)
  }
  let entry = if stmts.length() > 0 { stmts[0].id } else { -1 }
  { blocks: stmts, edges, entry, }
}

///|
/// Successor ids of a block, in edge order without duplicates.
pub fn successors(cfg : CFG, id : Int32) -> Array[Int32] {
  let out : Array[Int32] = []
  for edge in cfg.edges {
    if edge.0 == id && !out.contains(edge.1) {
      out.push(edge.1)
    }
  }
  out
}

///|
/// Transfer function of one block.
pub fn transfer(stmt : Stmt, incoming : Array[String]) -> Array[String] {
  match stmt.kind {
    Plain => sorted_unique(incoming)
    Source => union(incoming, stmt.vars)
    Sanitizer => difference(incoming, stmt.vars)
    Sink => sorted_unique(incoming)
  }
}

///|
/// May-taint state at block *entry*, keyed by block id. Unknown blocks have an
/// empty state. `Source` seeds names from inside the function; callers can also
/// seed parameters by passing them in an initial `Plain` block's `vars`.
pub fn solve(cfg : CFG) -> Map[Int32, Array[String]] {
  let states : Map[Int32, Array[String]] = Map([])
  for block in cfg.blocks {
    states.set(block.id, [])
  }
  if cfg.blocks.length() == 0 {
    return states
  }
  // Seed every block once: an empty incoming state is still a valid initial
  // value, so waiting for a state change would leave blocks unprocessed and a
  // Source would never propagate.
  let queue : Array[Int32] = []
  let queued : Map[Int32, Bool] = Map([])
  for block in cfg.blocks {
    queue.push(block.id)
    queued.set(block.id, true)
  }
  let mut head = 0
  while head < queue.length() {
    let id = queue[head]
    head += 1
    queued.set(id, false)
    let mut stmt : Stmt? = None
    for block in cfg.blocks {
      if block.id == id {
        stmt = Some(block)
        break
      }
    }
    let incoming = match states.get(id) {
      Some(value) => value
      None => []
    }
    let out = match stmt {
      Some(block) => transfer(block, incoming)
      None => incoming
    }
    for succ in successors(cfg, id) {
      let old = match states.get(succ) {
        Some(value) => value
        None => []
      }
      let merged = union(old, out)
      if !same_array(old, merged) {
        states.set(succ, merged)
        match queued.get(succ) {
          Some(true) => ()
          _ => {
            queue.push(succ)
            queued.set(succ, true)
          }
        }
      }
    }
  }
  states
}

///|
/// Reachable block ids from the entry, in deterministic edge order.
pub fn reachable(cfg : CFG) -> Array[Int32] {
  if cfg.blocks.length() == 0 {
    return []
  }
  let out : Array[Int32] = []
  let seen : Map[Int32, Bool] = Map([])
  let queue : Array[Int32] = [cfg.entry]
  seen.set(cfg.entry, true)
  let mut head = 0
  while head < queue.length() {
    let id = queue[head]
    head += 1
    out.push(id)
    for succ in successors(cfg, id) {
      match seen.get(succ) {
        Some(_) => ()
        None => {
          seen.set(succ, true)
          queue.push(succ)
        }
      }
    }
  }
  out
}
