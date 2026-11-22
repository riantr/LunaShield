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

name = "riantr/t4-cache-ignore"

version = "0.1.0"

readme = "README.mbt.md"

repository = ""

license = "Apache-2.0"

keywords = []

preferred_target = "wasm"

description = ""

import {
  "mizchi/bit_ignore@0.50.0",
  "gmlewis/sha256@0.18.3",
  "mizchi/bit_hash@0.50.0",
  "moonbitstack/mooncrypt@0.5.2",
}
