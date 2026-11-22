# sast scan CLI — exit codes, sharding, determinism

## --fail-on never downgrades a gate hit to exit 0

```mooncram
$ mkdir -p src && printf '%s' '[{"id":"JS001","language":"javascript","severity":"high","cwe":[95],"owasp":["A03:2021"],"query":"(call_expression function: (identifier) @callee arguments: (arguments . (_) @arg)) @call","predicates":[{"kind":"text_equals","capture":"callee","value":"eval"},{"kind":"not_has_prefix","capture":"arg","value":"\""}],"message":"Dynamic code execution via eval()","enabled":true}]' > rules.json && printf 'eval(userInput);\n' > src/a.js && scan.exe src --rules rules.json --format console --fail-on never
LunaShield 0.1.0
files: 1 scanned, 0 skipped, 1 raw hits
findings: 1 (critical 0, high 1, medium 0, low 0, info 0)
a.js:1:1 JS001 [high] Dynamic code execution via eval()
warnings: 0
```

## Invalid option value exits 2

```mooncram
$ mkdir -p src && printf '%s' '[]' > rules.json && scan.exe src --rules rules.json --fail-on bogus
error: unknown severity 'bogus', expected critical|high|medium|low|info|never
[2]
```

## Invalid shard value exits 2

```mooncram
$ mkdir -p src && printf '%s' '[]' > rules.json && scan.exe src --rules rules.json --shard 3/2
error: invalid shard '3/2', expected <i>/<n> with 0 <= i < n
[2]
```

## Unknown option exits 2

```mooncram
$ mkdir -p src && printf '%s' '[]' > rules.json && scan.exe src --rules rules.json --bogus
error: unknown option '--bogus'
[2]
```

## Missing rule pack exits 2 with the path in the message

```mooncram
$ mkdir -p src && scan.exe src --rules no-such-pack --format console
error: cannot read rules file: no-such-pack/rules.json
[2]
```

## Invalid rule pack exits 2 with a schema pointer

```mooncram
$ mkdir -p src && printf '%s' '[{"id":"BROKEN"}]' > rules.json && scan.exe src --rules rules.json --format console
error: rules file failed schema checks: /0/language: missing required field
[2]
```

## Shards partition the corpus: 0/2 plus 1/2 equals the full scan

```mooncram
$ mkdir -p src && printf '%s' '[{"id":"JS001","language":"javascript","severity":"high","cwe":[95],"owasp":["A03:2021"],"query":"(call_expression function: (identifier) @callee arguments: (arguments . (_) @arg)) @call","predicates":[{"kind":"text_equals","capture":"callee","value":"eval"},{"kind":"not_has_prefix","capture":"arg","value":"\""}],"message":"Dynamic code execution via eval()","enabled":true}]' > rules.json && printf 'eval(userInput);\n' > src/a.js && printf 'console.log(1);\n' > src/b.js && (scan.exe src --rules rules.json --shard 0/2 --format console > s0.txt; scan.exe src --rules rules.json --shard 1/2 --format console > s1.txt; cat s0.txt s1.txt | grep "^files:")
files: 1 scanned, 0 skipped, 0 raw hits
files: 1 scanned, 0 skipped, 1 raw hits
```

## Two runs produce byte-identical JSON

```mooncram
$ mkdir -p src && printf '%s' '[{"id":"JS001","language":"javascript","severity":"high","cwe":[95],"owasp":["A03:2021"],"query":"(call_expression function: (identifier) @callee arguments: (arguments . (_) @arg)) @call","predicates":[{"kind":"text_equals","capture":"callee","value":"eval"},{"kind":"not_has_prefix","capture":"arg","value":"\""}],"message":"Dynamic code execution via eval()","enabled":true}]' > rules.json && printf 'eval(userInput);\n' > src/a.js && (scan.exe src --rules rules.json --format json --out d1 > /dev/null; scan.exe src --rules rules.json --format json --out d2 > /dev/null; cmp d1/findings.json d2/findings.json && echo IDENTICAL)
IDENTICAL
```
