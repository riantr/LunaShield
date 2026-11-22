// Learn more about moon.mod configuration:
// https://docs.moonbitlang.com/en/latest/toolchain/moon/module.html
//
// To add a dependency, run this command in your terminal:
//   moon add moonbitlang/x
//
// Or manually declare it in `import`, for example:
// import {
//   "moonbitlang/x@0.4.6",
// }

name = "riantr/t11-t12-grammar"

version = "0.1.0"

readme = "README.mbt.md"

repository = ""

license = "Apache-2.0"

keywords = []

preferred_target = "wasm"

description = ""

import {
  "moonbit-community/tree-sitter-javascript@0.25.0",
  "moonbit-community/tree-sitter-typescript@0.23.2",
  "moonbit-community/tree-sitter-python@0.23.6",
  "moonbit-community/tree-sitter-java@0.23.5",
  "moonbit-community/tree-sitter-json@0.24.8",
  "moonbit-community/treesitter@0.1.1",
}
