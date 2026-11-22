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
