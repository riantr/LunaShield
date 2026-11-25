///|
#derive(@json.FromJson)
struct Case {
  file : String
  name : String
  src : String
}

///|
async fn main raise {
  let text = @fs.read_file("corpus/cases.json").text()
  let arr : Array[Case] = @json.from_json(@json.parse(text))
  let lang = @pkg.language()
  let parser = @treesitter.Parser::new()
  parser.set_language(lang)
  let mut ok = 0
  let mut bad = 0
  for c in arr {
    match parser.parse(@utf8.encode(c.src)) {
      None => {
        bad += 1
        println("NONE  " + c.file + "/" + c.name)
      }
      Some(tree) => {
        let root = tree.root_node()
        if root.has_error() {
          bad += 1
          println("ERROR " + c.file + "/" + c.name)
        } else {
          ok += 1
        }
      }
    }
  }
  println("TOTAL=" + (ok + bad).to_string() + " OK=" + ok.to_string() + " ERR=" + bad.to_string())
}
