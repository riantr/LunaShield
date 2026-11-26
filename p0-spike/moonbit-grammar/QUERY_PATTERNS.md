# MoonBit 规则 query 模板（基于探针实测）

`probe/main.mbt` 在真实 MoonBit 源码上验证了 tree-sitter query 的 capture 行为。
以下结论是后续 10 条规则设计的基础，**不要凭直觉写 query**。

## 实测结论

1. **无 named field 可用**：MoonBit grammar 的 257 个 named 节点全部没有
   named fields（`node-types.json` 的 `fields` 都是空数组）。所有 match 依赖
   子节点顺序和节点类型，不能写 `function:` / `arguments:` 这类字段锚点。
2. **query 可以编译并命中**：位置锚点 `.`、通配符 `(_)`、多 capture 的 pattern
   在 `@treesitter.Query::new` 下都工作正常。
3. **capture 稳定**：同名 capture 的 index 固定，重复运行结果逐字节一致。
4. **capture 返回顺序 ≠ index 顺序**：`m.captures()` 按节点在树中的位置返回，
   覆盖整个表达式的 `@call` 先返回，但它的 index 最大。
5. **primary 取最小 index**（`engine.mbt:183`）。因为 `@call` 写在 query 末尾，
   它的 index 最大，**primary 会落在第一个子节点 capture（通常是 `@pkg`）**。
   这与现有 JS 规则 `primary = callee` 的行为一致，snippet 是 callee 而非整个
   调用——可接受，但规则作者必须知道。
6. **位置锚点 `.` 是必须的**：`(arguments (argument) @arg)` 会为每个参数产生
   一个 match（写文件 `("p2", data)` 产生 2 条 finding）；`(arguments . (argument) @arg)`
   只匹配第一个参数。规则要捕获哪个参数就必须显式锚定。
7. **`fn` capture 带前导点**：`@fs.read_file(...)` 的 `@fn` 文本是 `.read_file`
   （不是 `read_file`）；`@process.Process::new(...)` 的 `@ty` 是 `.Process`，
   `@fn` 是 `new`。谓词值必须按此写。

## 三种可直接套用的 query 模板

### 模板 A：包函数调用（最高频，`@fs.read_file` / `@env.get_env_var` / `@crypto.md5`）

```
(apply_expression
  (qualified_identifier (package_identifier) @pkg (dot_lowercase_identifier) @fn)
  (arguments . (argument) @arg)) @call
```

谓词（host-side `PredicateSpec`）：

```
pkg text_equals "@fs"
fn  text_equals ".read_file"
```

- 要捕获第 2 个参数（已实测，两种写法等价）：
  `(arguments (argument) . (argument) @arg)` 或
  `(arguments (argument) _ . (argument) @arg)`，都只命中 `data` 一个 match
- 要捕获整个参数列表：把 `(arguments . (argument) @arg)` 改成 `(arguments) @args`
- taint sink 的 `capture` 填 `"arg"`

### 模板 B：类型构造函数（`@process.Process::new` / `@tls.Config::new`）

```
(apply_expression
  (method_expression
    (type_name (qualified_type_identifier (package_identifier) @pkg (dot_identifier (dot_uppercase_identifier) @ty)))
    (lowercase_identifier) @fn)
  (arguments . (argument) @arg)) @call
```

谓词：`pkg == "@process"`，`ty == ".Process"`，`fn == "new"`。

### 模板 C：硬编码常量（`const API_KEY : String = "..."`）

```
(const_definition
  (uppercase_identifier) @name
  (type_annotation)
  (atomic_expression (literal (string_literal) @str))) @decl
```

谓词：`name contains "KEY"` / `name contains "SECRET"` / `name contains "TOKEN"`，
或 `str has_prefix "sk_"`。primary 是 `@name`（index 0），snippet 是常量名。

## 补充的四个实测模板（第二批探针，11/11 PASS）

### 模板 D：字符串插值污点（`"id=\{id}"`）

```
(string_interpolation (interpolator (qualified_identifier (lowercase_identifier) @var))) @str
```

- `@str` 文本是整段含引号的字面量 `"id=\{id}"`，`@var` 是 `id`。
- 对应 MB002/MB007 的污点路径：sink capture 填 `"str"`，source 声明 identifier
  `id`；注入的插值表达式还可来自 method/apply 节点，把
  `(qualified_identifier (lowercase_identifier) @var)` 换成 `(_) @var` 即可泛化。
- 注意 MoonBit 源码里反斜杠要写 `\\{id}`，query 里节点名是 `string_interpolation`
  / `interpolator`（`grammar.json` 中 `interpolator` = `\{` + expression + `}`）。

### 模板 E：多行字符串密钥（`const KEY : String = #|...|#`）

```
(const_definition
  (uppercase_identifier) @name
  (type_annotation)
  (atomic_expression (literal
    (multiline_string_literal (multiline_string_fragment (multiline_string_content) @secret))))) @decl
```

- **坑**：`@secret` 文本是 `sk_live_1234567890|#`，**带闭合符 `|#`**
  （`multiline_string_content` 是 `[^\n]*`，贪心吃到行尾）。不能对 @secret 做
  `text_equals`/`has_suffix` 判断完整密钥；用 `has_prefix "sk_"` 或
  `contains "sk_live_"` 这类前缀/包含谓词。
- 普通双引号密钥走模板 C，`@str` 不带闭合符。

### 模板 F：空 catch（`try { ... } catch { }`）

```
((try_catch_clause) @catch (#not-match? @catch "=>"))
```

- `case_clause` 语法必含 `=>`，所以"没有 `=>`"等价于"没有 case 分支"，
  即空 catch。实测：空 catch 命中 1，带 `e => println(e)` 命中 0。
- **坑**：谓词必须和 capture 一起包在**外层括号**里。写成
  `(try_catch_clause) @catch (#not-match? @catch "=>")` 会把 predicate 拆成
  独立 pattern，结果匹配树上每个节点（实测空 catch 24 个 match、非空 36 个）。
- 引擎侧不需要改谓词白名单：`#not-match?` 是 query 字符串里的原生谓词，
  `Query::new` 自身解析并应用。

### 模板 G：第二参数锚定的两种写法（都已实测）

```
(arguments (argument) . (argument) @arg)
(arguments (argument) _ . (argument) @arg)
```

两者都精确命中 `@fs.write_file(path, data)` 的 `data`，各产生 1 个 match，
capture 文本一致。文档早期推测第二种写法会落空，实测证伪。

## 复现

```bash
cd p0-spike/moonbit-grammar
moon build --target native probe
./_build/native/debug/build/probe/probe.exe
# PROBE TOTAL=11 PASS=11 FAIL=0
```
