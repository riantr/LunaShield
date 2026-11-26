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

- 要捕获第 2 个参数：把 `. (argument) @arg` 改成 `(argument) _ . (argument) @arg`
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

## 尚未验证、写规则前需补探针的模式

- 字符串插值内的污点（`"..." + id` 的 `binary_expression` 已验证可命中；
  MoonBit 的 `\{expr}` 插值节点 `string_interpolation` 还没测）
- `@fs.write_file(path, data)` 第 2 参数的锚定写法
- 多行字符串 `#|...|#` 内的硬编码密钥
- `try_catch_expression` 的空 catch 检测（模板待设计）

## 复现

```bash
cd p0-spike/moonbit-grammar
moon build --target native probe
./_build/native/debug/build/probe/probe.exe
# PROBE TOTAL=5 PASS=5 FAIL=0
```
