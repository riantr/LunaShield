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

## Incremental cache: second run hits and output is unchanged

```mooncram
$ rm -rf w && mkdir -p w/src && printf '%s' '[{"id":"JS001","language":"javascript","severity":"high","cwe":[95],"owasp":["A03:2021"],"query":"(call_expression function: (identifier) @callee arguments: (arguments . (_) @arg)) @call","predicates":[{"kind":"text_equals","capture":"callee","value":"eval"},{"kind":"not_has_prefix","capture":"arg","value":"\""}],"message":"Dynamic code execution via eval()","enabled":true}]' > w/rules.json && printf 'eval(userInput);\n' > w/src/a.js && (scan.exe w/src --rules w/rules.json --format json --out w/full > /dev/null; scan.exe w/src --rules w/rules.json --format json --out w/inc --incremental --cache-dir w/cache > /dev/null; cmp w/full/findings.json w/inc/findings.json && echo SAME; scan.exe w/src --rules w/rules.json --format console --incremental --cache-dir w/cache | tail -1)
SAME
cache: 1 hit, 0 miss
```

## Fast cache: probe replay, and the mtime trade-off it buys

The fast path trusts `(size, mtime)` and never reads the body, so the second run
replays without touching the file. That is a real trade: a file rewritten to the
same size inside the same mtime tick keeps the old verdict until it is touched.
The strict path hashes content and therefore sees the rewrite immediately.

```mooncram
$ rm -rf wf && mkdir -p wf/src && printf '%s' '[{"id":"JS001","language":"javascript","severity":"high","cwe":[95],"owasp":["A03:2021"],"query":"(call_expression function: (identifier) @callee arguments: (arguments . (_) @arg)) @call","predicates":[{"kind":"text_equals","capture":"callee","value":"eval"},{"kind":"not_has_prefix","capture":"arg","value":"\""}],"message":"Dynamic code execution via eval()","enabled":true}]' > wf/rules.json && printf 'function f(req) {{ eval(req.query.x); }}\n' > wf/src/a.js && scan.exe wf/src --rules wf/rules.json --format console --fast-cache --cache-dir wf/cache | tail -1 && scan.exe wf/src --rules wf/rules.json --format console --fast-cache --cache-dir wf/cache | tail -1 && cp -p wf/src/a.js wf/ref.js && printf 'function f(req) {{ exec(req.query.x); }}\n' > wf/src/a.js && touch -r wf/ref.js wf/src/a.js && scan.exe wf/src --rules wf/rules.json --format console --incremental --cache-dir wf/cache | grep 'findings:' && scan.exe wf/src --rules wf/rules.json --format console --fast-cache --cache-dir wf/cache | grep 'findings:' && touch wf/src/a.js && scan.exe wf/src --rules wf/rules.json --format console --fast-cache --cache-dir wf/cache | grep 'findings:'
cache: 0 hit, 1 miss
cache: 1 hit, 0 miss
findings: 0 (critical 0, high 0, medium 0, low 0, info 0)
findings: 1 (critical 0, high 1, medium 0, low 0, info 0)
findings: 0 (critical 0, high 0, medium 0, low 0, info 0)
```
