# End-to-end Finding output

Each code block is one isolated shell expression in a fresh temp directory;
`moon cram test` puts the built `main.exe` on PATH.

## Detects an eval call and emits a JSON finding

```mooncram
$ printf 'eval(userInput);\n' > sample.js && main.exe sample.js
{"file":"sample.js","finding_count":1,"findings":[{"rule_id":"JS001","severity":"HIGH","line":1,"column":1,"snippet":"eval","fingerprint":"cad6a9d402bd4d6c926a60f7d06d046c4fdf4b613dab5be32c2189e45cd3da31"}]}
```

## Clean sample produces no findings

```mooncram
$ printf 'const x = 1;\n' > clean.js && main.exe clean.js
{"file":"clean.js","finding_count":0,"findings":[]}
```

## Missing argument prints usage and exits non-zero

```mooncram
$ main.exe
usage: p0-e2e <file.js>
[127]
```
