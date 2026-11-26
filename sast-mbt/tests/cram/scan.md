# sast scan CLI — detection and reporting

Each `mooncram` block runs in its own temp directory with the built `scan.exe` on
PATH, so every fixture (rule pack included) is created inside the same shell
expression. `[N]` marks a non-zero exit code.

## Detects eval and exits 1 (gate hit)

```mooncram
$ mkdir -p src && printf '%s' '[{"id":"JS001","language":"javascript","severity":"high","cwe":[95],"owasp":["A03:2021"],"query":"(call_expression function: (identifier) @callee arguments: (arguments . (_) @arg)) @call","predicates":[{"kind":"text_equals","capture":"callee","value":"eval"},{"kind":"not_has_prefix","capture":"arg","value":"\""}],"message":"Dynamic code execution via eval()","enabled":true}]' > rules.json && printf 'eval(userInput);\n' > src/a.js && scan.exe src --rules rules.json --format console
LunaShield 0.1.0
files: 1 scanned, 0 skipped, 1 raw hits
findings: 1 (critical 0, high 1, medium 0, low 0, info 0)
a.js:1:1 JS001 [high] Dynamic code execution via eval()
warnings: 0
[1]
```

## Clean file exits 0

```mooncram
$ mkdir -p src && printf '%s' '[{"id":"JS001","language":"javascript","severity":"high","cwe":[95],"owasp":["A03:2021"],"query":"(call_expression function: (identifier) @callee arguments: (arguments . (_) @arg)) @call","predicates":[{"kind":"text_equals","capture":"callee","value":"eval"},{"kind":"not_has_prefix","capture":"arg","value":"\""}],"message":"Dynamic code execution via eval()","enabled":true}]' > rules.json && printf 'console.log(1);\n' > src/a.js && scan.exe src --rules rules.json --format console
LunaShield 0.1.0
files: 1 scanned, 0 skipped, 0 raw hits
findings: 0 (critical 0, high 0, medium 0, low 0, info 0)
warnings: 0
```

## String-literal argument is not reported (predicate works)

```mooncram
$ mkdir -p src && printf '%s' '[{"id":"JS001","language":"javascript","severity":"high","cwe":[95],"owasp":["A03:2021"],"query":"(call_expression function: (identifier) @callee arguments: (arguments . (_) @arg)) @call","predicates":[{"kind":"text_equals","capture":"callee","value":"eval"},{"kind":"not_has_prefix","capture":"arg","value":"\""}],"message":"Dynamic code execution via eval()","enabled":true}]' > rules.json && printf 'eval("console.log(1)");\n' > src/a.js && scan.exe src --rules rules.json --format console
LunaShield 0.1.0
files: 1 scanned, 0 skipped, 0 raw hits
findings: 0 (critical 0, high 0, medium 0, low 0, info 0)
warnings: 0
```

## JSON report goes to --out and keeps the P0 fingerprint

```mooncram
$ mkdir -p src && printf '%s' '[{"id":"JS001","language":"javascript","severity":"high","cwe":[95],"owasp":["A03:2021"],"query":"(call_expression function: (identifier) @callee arguments: (arguments . (_) @arg)) @call","predicates":[{"kind":"text_equals","capture":"callee","value":"eval"},{"kind":"not_has_prefix","capture":"arg","value":"\""}],"message":"Dynamic code execution via eval()","enabled":true}]' > rules.json && printf 'eval(userInput);\n' > src/a.js && (scan.exe src --rules rules.json --format json --out out > /dev/null; cat out/findings.json)
{"version":"0.1.0","stats":{"files_scanned":1,"files_skipped":0,"bytes_scanned":17,"raw_hits":1},"warnings":[],"skipped_files":[],"findings":[{"rule_id":"JS001","severity":"high","confidence":"high","cwe":[95],"owasp":["A03:2021"],"primary":{"path":"a.js","line":1,"column":1,"byte_offset":0},"message":"Dynamic code execution via eval()","snippet":"eval","fingerprint":"cad6a9d402bd4d6c926a60f7d06d046c4fdf4b613dab5be32c2189e45cd3da31"}]}
```

## Syntax error is reported as a warning and the scan continues

```mooncram
$ mkdir -p src && printf '%s' '[{"id":"JS001","language":"javascript","severity":"high","cwe":[],"owasp":[],"query":"(class_declaration name: (identifier) @x)","predicates":[],"message":"class found","enabled":true}]' > rules.json && printf 'function f( {\n' > src/a.js && scan.exe src --rules rules.json --format console
LunaShield 0.1.0
files: 1 scanned, 0 skipped, 0 raw hits
findings: 0 (critical 0, high 0, medium 0, low 0, info 0)
warnings: 1
a.js:1:1 syntax error
```

## SARIF report keeps rule id, level and fingerprint

```mooncram
$ mkdir -p src && printf '%s' '[{"id":"JS001","language":"javascript","severity":"high","cwe":[95],"owasp":["A03:2021"],"query":"(call_expression function: (identifier) @callee arguments: (arguments . (_) @arg)) @call","predicates":[{"kind":"text_equals","capture":"callee","value":"eval"},{"kind":"not_has_prefix","capture":"arg","value":"\""}],"message":"Dynamic code execution via eval()","enabled":true}]' > rules.json && printf 'eval(userInput);\n' > src/a.js && (scan.exe src --rules rules.json --format sarif --out out > /dev/null; grep -o '"ruleId":"JS001"' out/findings.sarif; grep -o '"level":"error"' out/findings.sarif; grep -o '"startLine":1' out/findings.sarif)
"ruleId":"JS001"
"level":"error"
"startLine":1
```

## `--taint report` annotates confidence without dropping findings

```mooncram
$ mkdir -p src && printf '%s' '[{"id":"JS001","language":"javascript","severity":"high","cwe":[95],"owasp":[],"query":"(call_expression function: (identifier) @callee arguments: (arguments . (_) @arg)) @call","predicates":[{"kind":"text_equals","capture":"callee","value":"eval"}],"message":"eval","enabled":true}]' > rules.json && printf '%s' '{"version":"1.0.0","languages":[{"language":"javascript","sources":[{"name":"q","node_kind":"member_expression","text_contains":"req.query"}],"sanitizers":[{"name":"esc","callee_contains":"escapeHtml"}],"sinks":[{"rule_id":"JS001","capture":"arg"}]}]}' > taint.json && printf 'function f(req) { eval(req.query.x); }\n' > src/a.js && printf 'function f(req) { eval(escapeHtml(req.query.x)); }\n' > src/b.js && (scan.exe src --rules rules.json --taint report --format json --out out --fail-on never > /dev/null; grep -o '"confidence":"[a-z]*"' out/findings.json)
"confidence":"high"
"confidence":"low"
```

## `--taint strict` drops only the refuted finding

```mooncram
$ mkdir -p src && printf '%s' '[{"id":"JS001","language":"javascript","severity":"high","cwe":[95],"owasp":[],"query":"(call_expression function: (identifier) @callee arguments: (arguments . (_) @arg)) @call","predicates":[{"kind":"text_equals","capture":"callee","value":"eval"}],"message":"eval","enabled":true}]' > rules.json && printf '%s' '{"version":"1.0.0","languages":[{"language":"javascript","sources":[{"name":"q","node_kind":"member_expression","text_contains":"req.query"}],"sanitizers":[{"name":"esc","callee_contains":"escapeHtml"}],"sinks":[{"rule_id":"JS001","capture":"arg"}]}]}' > taint.json && printf 'function f(req) { eval(req.query.x); }\n' > src/a.js && printf 'function f(req) { eval(escapeHtml(req.query.x)); }\n' > src/b.js && scan.exe src --rules rules.json --taint strict --format console --fail-on never
LunaShield 0.1.0
files: 2 scanned, 0 skipped, 2 raw hits
findings: 1 (critical 0, high 1, medium 0, low 0, info 0)
a.js:1:19 JS001 [high] eval
warnings: 0
```

## `--taint off` keeps the pre-taint output byte for byte

```mooncram
$ mkdir -p src && printf '%s' '[{"id":"JS001","language":"javascript","severity":"high","cwe":[95],"owasp":[],"query":"(call_expression function: (identifier) @callee arguments: (arguments . (_) @arg)) @call","predicates":[{"kind":"text_equals","capture":"callee","value":"eval"}],"message":"eval","enabled":true}]' > rules.json && printf '%s' '{"version":"1.0.0","languages":[{"language":"javascript","sources":[{"name":"q","node_kind":"member_expression","text_contains":"req.query"}],"sanitizers":[{"name":"esc","callee_contains":"escapeHtml"}],"sinks":[{"rule_id":"JS001","capture":"arg"}]}]}' > taint.json && printf 'function f(req) { eval(req.query.x); }\n' > src/a.js && printf 'function f(req) { eval(escapeHtml(req.query.x)); }\n' > src/b.js && scan.exe src --rules rules.json --taint off --format console --fail-on never
LunaShield 0.1.0
files: 2 scanned, 0 skipped, 2 raw hits
findings: 2 (critical 0, high 2, medium 0, low 0, info 0)
a.js:1:19 JS001 [high] eval
b.js:1:19 JS001 [high] eval
warnings: 0
```

## MoonBit `.mb` file is scanned with the vendored grammar

```mooncram
$ mkdir -p mb && printf '%s' '[{"id":"MB001","language":"moonbit","severity":"high","cwe":[78],"owasp":["A03:2021"],"query":"(apply_expression (qualified_identifier (package_identifier) @pkg (dot_lowercase_identifier) @fn) (arguments . (argument) @arg)) @call","predicates":[{"kind":"text_equals","capture":"pkg","value":"@process"},{"kind":"text_equals","capture":"fn","value":".run"},{"kind":"not_has_prefix","capture":"arg","value":"\""}],"message":"Command injection: process.run with untrusted command","enabled":true}]' > rules.json && printf 'fn main {\n  @process.run(cmd, args)\n}\n' > mb/a.mb && scan.exe mb --rules rules.json --format console
LunaShield 0.1.0
files: 1 scanned, 0 skipped, 1 raw hits
findings: 1 (critical 0, high 1, medium 0, low 0, info 0)
a.mb:2:3 MB001 [high] Command injection: process.run with untrusted command
warnings: 0
[1]
```

## Invalid `--taint` mode is an argument error

```mooncram
$ scan.exe . --taint bogus
error: unknown taint mode 'bogus', expected off|report|strict
[2]
```
