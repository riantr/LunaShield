// Port of moonbitlang/tree-sitter-moonbit src/scanner.c (550 lines).
// Token ids and logic mirror the C enum one-for-one.

const SCANNER_RESET : Int32 = 0
const AUTOMATIC_SEMICOLON : Int32 = 1
const SEMICOLON : Int32 = 2
const MULTILINE_STRING_SEPARATOR : Int32 = 3
const MULTILINE_INTERPOLATION_SEPARATOR : Int32 = 4
const FLOAT_LITERAL : Int32 = 5
const FOR_KEYWORD : Int32 = 6
const ERROR_SENTINEL : Int32 = 7

///|
priv struct ScannerState {
  mut remove_semi : Bool
  mut multiline_string : Bool
}

///|
fn iswblank(c : Int32) -> Bool {
  c == ' ' || c == '\t'
}

///|
fn iswspace(c : Int32) -> Bool {
  c == ' ' || (c >= '\t' && c <= '\r')
}

///|
fn iswdigit(c : Int32) -> Bool {
  c >= '0' && c <= '9'
}

///|
fn iswxdigit(c : Int32) -> Bool {
  iswdigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

///|
fn iswalpha(c : Int32) -> Bool {
  (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

///|
fn advance(lexer : @runtime.Lexer) -> Unit {
  lexer.advance(false)
}

///|
fn skip(lexer : @runtime.Lexer) -> Unit {
  lexer.advance(true)
}

///|
fn skip_spaces(lexer : @runtime.Lexer, valid_symbols : ArrayView[Bool]) -> Unit {
  if !valid_symbols[AUTOMATIC_SEMICOLON] {
    while iswspace(lexer.lookahead) && !lexer.eof() {
      skip(lexer)
    }
  } else {
    while iswblank(lexer.lookahead) && !lexer.eof() {
      skip(lexer)
    }
  }
}

priv enum FloatLiteralResult {
  Ok
  Not
  Err
}

///|
fn scan_decimal_frac(lexer : @runtime.Lexer) -> FloatLiteralResult {
  if lexer.lookahead == '.' {
    return Err
  }
  while iswdigit(lexer.lookahead) || lexer.lookahead == '_' {
    advance(lexer)
  }
  if lexer.lookahead == 'e' || lexer.lookahead == 'E' {
    advance(lexer)
    if lexer.lookahead == '+' || lexer.lookahead == '-' {
      advance(lexer)
    }
    while iswdigit(lexer.lookahead) || lexer.lookahead == '_' {
      advance(lexer)
    }
  }
  Ok
}

///|
fn scan_decimal(lexer : @runtime.Lexer) -> FloatLiteralResult {
  while iswdigit(lexer.lookahead) || lexer.lookahead == '_' {
    advance(lexer)
  }
  if lexer.lookahead != '.' {
    return Err
  }
  advance(lexer)
  scan_decimal_frac(lexer)
}

///|
fn scan_float_literal(
  lexer : @runtime.Lexer,
  valid_symbols : ArrayView[Bool],
) -> FloatLiteralResult {
  skip_spaces(lexer, valid_symbols)
  if !iswdigit(lexer.lookahead) {
    return Not
  }
  if lexer.lookahead == '0' {
    advance(lexer)
    if lexer.lookahead == '.' {
      advance(lexer)
      return scan_decimal_frac(lexer)
    }
    if iswdigit(lexer.lookahead) {
      advance(lexer)
      return scan_decimal(lexer)
    }
    if lexer.lookahead != 'x' && lexer.lookahead != 'X' {
      return Err
    }
    advance(lexer)
    while iswxdigit(lexer.lookahead) || lexer.lookahead == '_' {
      advance(lexer)
    }
    if lexer.lookahead != '.' {
      return Err
    }
    advance(lexer)
    if lexer.lookahead == '.' {
      return Err
    }
    while iswxdigit(lexer.lookahead) || lexer.lookahead == '_' {
      advance(lexer)
    }
    if lexer.lookahead == 'p' || lexer.lookahead == 'P' {
      advance(lexer)
      if lexer.lookahead == '+' || lexer.lookahead == '-' {
        advance(lexer)
      }
      while iswdigit(lexer.lookahead) {
        advance(lexer)
      }
    }
    return Ok
  } else {
    advance(lexer)
    scan_decimal(lexer)
  }
}

#derive(Eq)
enum AsiResult {
  Remove
  Insert
  Skip
}

///|
fn asi_symbol_end(lexer : @runtime.Lexer) -> AsiResult {
  if iswalpha(lexer.lookahead) || lexer.lookahead == '_' {
    Insert
  } else {
    Remove
  }
}

///|
fn test_symbol(lexer : @runtime.Lexer, expected : String) -> Bool {
  for i = 0; i < expected.length(); i = i + 1 {
    if lexer.lookahead != expected[i].to_int() {
      return false
    }
    advance(lexer)
  }
  !(iswalpha(lexer.lookahead) || lexer.lookahead == '_')
}

///|
fn asi_symbol(lexer : @runtime.Lexer, expected : String) -> AsiResult {
  for i = 0; i < expected.length(); i = i + 1 {
    if lexer.lookahead != expected[i].to_int() {
      return Insert
    }
    advance(lexer)
  }
  asi_symbol_end(lexer)
}

///|
fn can_insert_semi(lexer : @runtime.Lexer, state : ScannerState) -> AsiResult {
  if state.multiline_string {
    match lexer.lookahead {
      '#' => {
        advance(lexer)
        if lexer.lookahead == '|' {
          return Remove
        }
      }
      '$' => {
        advance(lexer)
        if lexer.lookahead == '|' {
          return Remove
        }
      }
      _ => ()
    }
  }
  match lexer.lookahead {
    '+' => {
      advance(lexer)
      if lexer.lookahead == '=' { Remove } else { Insert }
    }
    '-' => {
      advance(lexer)
      if lexer.lookahead == '=' { Remove } else { Insert }
    }
    '*' => {
      advance(lexer)
      if lexer.lookahead == '=' { Remove } else { Insert }
    }
    '/' => {
      advance(lexer)
      match lexer.lookahead {
        '/' => Skip
        '=' => Remove
        _ => Insert
      }
    }
    '|' => {
      advance(lexer)
      match lexer.lookahead {
        '>' => Remove
        '|' => Insert
        _ => Remove
      }
    }
    '<' => {
      advance(lexer)
      match lexer.lookahead {
        '+' | '?' | '|' => Remove
        _ => Insert
      }
    }
    '%' => {
      advance(lexer)
      if lexer.lookahead == '=' { Remove } else { Insert }
    }
    '.' => {
      advance(lexer)
      if lexer.lookahead == '.' {
        advance(lexer)
        if lexer.lookahead == '.' {
          advance(lexer)
          Insert
        } else {
          Remove
        }
      } else {
        Remove
      }
    }
    '!' => {
      advance(lexer)
      while iswblank(lexer.lookahead) {
        advance(lexer)
      }
      if lexer.lookahead == '(' || lexer.lookahead == '!' || lexer.lookahead == '=' {
        Remove
      } else {
        Insert
      }
    }
    ':' | ',' | ')' | ']' | ';' | '=' | '?' => Remove
    'a' => {
      advance(lexer)
      if lexer.lookahead == 's' {
        advance(lexer)
        asi_symbol_end(lexer)
      } else {
        Insert
      }
    }
    'i' => {
      advance(lexer)
      if lexer.lookahead == 's' || lexer.lookahead == 'n' {
        advance(lexer)
        asi_symbol_end(lexer)
      } else {
        Insert
      }
    }
    'e' => {
      advance(lexer)
      asi_symbol(lexer, "lse")
    }
    'c' => {
      advance(lexer)
      asi_symbol(lexer, "atch")
    }
    'd' => {
      advance(lexer)
      asi_symbol(lexer, "erive")
    }
    'w' => {
      advance(lexer)
      asi_symbol(lexer, "ith")
    }
    'n' => {
      advance(lexer)
      asi_symbol(lexer, "obreak")
    }
    _ => Insert
  }
}

///|
fn reset_state(state : ScannerState) -> Unit {
  state.remove_semi = false
  state.multiline_string = false
}

///|
fn moonbit_scan(
  state : ScannerState,
  lexer : @runtime.Lexer,
  valid_symbols : ArrayView[Bool],
) -> Bool {
  if lexer.eof() {
    return false
  }
  if valid_symbols[ERROR_SENTINEL] {
    return false
  }

  if valid_symbols[FLOAT_LITERAL] {
    match scan_float_literal(lexer, valid_symbols) {
      Ok => {
        lexer.mark_end()
        lexer.result_symbol = FLOAT_LITERAL
        return true
      }
      Err => return false
      Not => ()
    }
  }

  if valid_symbols[MULTILINE_STRING_SEPARATOR] ||
     valid_symbols[MULTILINE_INTERPOLATION_SEPARATOR] {
    skip_spaces(lexer, valid_symbols)
    if valid_symbols[MULTILINE_STRING_SEPARATOR] && lexer.lookahead == '#' {
      advance(lexer)
      if lexer.lookahead == '|' {
        advance(lexer)
        lexer.result_symbol = MULTILINE_STRING_SEPARATOR
        lexer.mark_end()
        state.multiline_string = true
        return true
      }
    } else if valid_symbols[MULTILINE_INTERPOLATION_SEPARATOR] &&
              lexer.lookahead == '$' {
      advance(lexer)
      if lexer.lookahead == '|' {
        advance(lexer)
        lexer.result_symbol = MULTILINE_INTERPOLATION_SEPARATOR
        lexer.mark_end()
        state.multiline_string = true
        return true
      }
    }
  }

  if valid_symbols[FOR_KEYWORD] {
    skip_spaces(lexer, valid_symbols)
    if test_symbol(lexer, "for") {
      lexer.result_symbol = FOR_KEYWORD
      lexer.mark_end()
      state.remove_semi = true
      return true
    }
  }

  if valid_symbols[SEMICOLON] {
    skip_spaces(lexer, valid_symbols)
    if lexer.lookahead == ';' {
      advance(lexer)
      lexer.result_symbol = SEMICOLON
      lexer.mark_end()
      state.remove_semi = true
      return true
    }
  }

  if valid_symbols[AUTOMATIC_SEMICOLON] {
    while iswblank(lexer.lookahead) {
      skip(lexer)
    }
    if lexer.lookahead != '\n' {
      return false
    }
    advance(lexer)
    lexer.result_symbol = AUTOMATIC_SEMICOLON
    lexer.mark_end()
    while iswspace(lexer.lookahead) {
      advance(lexer)
    }
    let mut insert_semi = can_insert_semi(lexer, state)
    if insert_semi == Skip {
      return false
    }
    if state.remove_semi {
      insert_semi = Remove
    }
    if state.remove_semi || state.multiline_string {
      reset_state(state)
      if insert_semi == Remove {
        lexer.result_symbol = SCANNER_RESET
        return true
      }
    }
    return insert_semi == Insert
  }

  if valid_symbols[SCANNER_RESET] && state.remove_semi {
    lexer.result_symbol = SCANNER_RESET
    lexer.mark_end()
    state.remove_semi = false
    reset_state(state)
    return true
  }

  false
}

///|
pub fn moonbit_scanner() -> @runtime.ExternalScanner {
  let state : ScannerState = { remove_semi: false, multiline_string: false }
  {
    scan: (lexer, valid_symbols) => moonbit_scan(state, lexer, valid_symbols),
    serialize: (buffer : FixedArray[Byte]) => {
      buffer[0] = if state.remove_semi { 1 } else { 0 }
      buffer[1] = if state.multiline_string { 1 } else { 0 }
      2
    },
    deserialize: (buffer : BytesView) => {
      reset_state(state)
      if buffer.length() == 2 {
        state.remove_semi = buffer[0] != 0
        state.multiline_string = buffer[1] != 0
      }
    },
    destroy: () => (),
  }
}
