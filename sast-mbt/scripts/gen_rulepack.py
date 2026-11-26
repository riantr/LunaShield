#!/usr/bin/env python3
"""Generate the official rule pack (60 rules: 50 MVP + 10 MoonBit) and fixtures.

One-off authoring helper: the generated `rules.json` and fixtures are the
committed source of truth, this script only makes it feasible to write 60 rules
plus 180 fixture files without copy-paste drift. Re-run after editing the table.

Usage:
    python3 scripts/gen_rulepack.py            # write files
    python3 scripts/gen_rulepack.py --check    # verify files are up to date
"""

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACK = ROOT / "rulepacks" / "official"
FIXTURES = ROOT / "tests" / "fixtures"

# --- query shapes -----------------------------------------------------------
JS_CALL_ARG = '(call_expression function: (identifier) @callee arguments: (arguments . (_) @arg)) @call'
JS_CALL_PROP = '(call_expression function: (member_expression object: (identifier) @obj property: (property_identifier) @prop) arguments: (arguments . (_) @arg)) @call'
JS_CALL_PROP_NOARG = '(call_expression function: (member_expression object: (identifier) @obj property: (property_identifier) @prop)) @call'
JS_NEW = '(new_expression constructor: (identifier) @ctor arguments: (arguments . (_) @arg)) @call'
JS_MEMBER_ASSIGN = '(assignment_expression left: (member_expression property: (property_identifier) @prop) right: (_) @val) @assign'
JS_VAR_STR = '(variable_declarator name: (identifier) @name value: (string) @val) @decl'
TS_AS = '(as_expression (predefined_type) @t) @cast'
TSX_ATTR = '(jsx_attribute (property_identifier) @name) @attr'
TSX_ATTR_STR = '(jsx_attribute (property_identifier) @name (string) @val) @attr'
PY_CALL = '(call function: (identifier) @callee arguments: (argument_list . (_) @arg)) @call'
PY_METHOD = '(call function: (attribute object: (identifier) @obj attribute: (identifier) @prop) arguments: (argument_list . (_) @arg)) @call'
PY_METHOD_NAME = '(call function: (attribute attribute: (identifier) @prop)) @call'
PY_KWARG_TRUE = '(keyword_argument name: (identifier) @kw value: (true) @val) @arg'
PY_KWARG_FALSE = '(keyword_argument name: (identifier) @kw value: (false) @val) @arg'
PY_ASSIGN_STR = '(assignment left: (identifier) @name right: (_) @val) @assign'
JAVA_CALL = '(method_invocation name: (identifier) @name arguments: (argument_list . (_) @arg)) @call'
JAVA_CALL_PLAIN = '(method_invocation name: (identifier) @name) @call'
JAVA_NEW = '(object_creation_expression type: (type_identifier) @t arguments: (argument_list . (_) @arg)) @new'
JAVA_LOCAL_STR = '(local_variable_declaration declarator: (variable_declarator name: (identifier) @name value: (string_literal) @val)) @decl'
JSON_PAIR_STR = '(pair key: (string) @key value: (string) @val) @pair'
JSON_PAIR_TRUE = '(pair key: (string) @key value: (true) @val) @pair'
JSON_PAIR_FALSE = '(pair key: (string) @key value: (false) @val) @pair'
MB_CALL_PKG = '(apply_expression (qualified_identifier (package_identifier) @pkg (dot_lowercase_identifier) @fn) (arguments . (argument) @arg)) @call'
MB_RAND_METHOD = '(apply_expression (method_expression (type_name (qualified_type_identifier (package_identifier) @pkg (dot_identifier (dot_uppercase_identifier) @ty))) (lowercase_identifier) @fn) (arguments)) @call'
MB_TLS_VERIFY = '(apply_expression (method_expression (type_name (qualified_type_identifier (package_identifier) @pkg (dot_identifier (dot_uppercase_identifier) @ty))) (lowercase_identifier) @fn) (arguments (argument) (argument (labelled_argument (lowercase_identifier) @label (atomic_expression (literal (boolean_literal) @val)))))) @call'
MB_ENV_LOG = '(apply_expression (qualified_identifier (lowercase_identifier) @fn) (arguments . (argument (apply_expression (qualified_identifier (package_identifier) @pkg (dot_lowercase_identifier) @getter) (arguments . (argument) @key))))) @call'
MB_CONST_STR = '(const_definition (uppercase_identifier) @name (type_annotation) (atomic_expression (literal (string_literal) @str))) @decl'
MB_EXTERN = '(function_definition (external_linkage (string_literal) @lib) (function_identifier) @fn) @decl'
MB_HMAC = '(apply_expression (qualified_identifier (package_identifier) @pkg (dot_lowercase_identifier) @fn) (arguments (argument) (argument) (argument (labelled_argument (lowercase_identifier) @label (constructor_expression (uppercase_identifier) @alg))))) @call'
MB_EMPTY_CATCH = '((try_catch_clause) @catch (#not-match? @catch "=>"))'

QUOTE = '"'


def p(kind, capture, value):
    return {"kind": kind, "capture": capture, "value": value}


def cond(capture):
    """Capture text must not be a string literal (starts with a quote)."""
    return p("not_has_prefix", capture, QUOTE)


# --- rule table -------------------------------------------------------------
# (id, language, severity, cwe, owasp, query, predicates, message, positive, negative)
JS_LINE = "// vulnerable: "
JS_SAFE = "// safe: "

RULES = [
    # ---- JavaScript (JS001-JS010) ----
    (
        "JS001", "javascript", "high", [95], ["A03:2021"], JS_CALL_ARG,
        [p("text_equals", "callee", "eval"), cond("arg")],
        "Dynamic code execution via eval()",
        "eval(userInput);",
        "compute(userInput);",
    ),
    (
        "JS002", "javascript", "high", [95], ["A03:2021"], JS_NEW,
        [p("text_equals", "ctor", "Function"), cond("arg")],
        "Dynamic code execution via new Function()",
        "new Function(userInput);",
        "new Widget(userInput);",
    ),
    (
        "JS003", "javascript", "high", [79], ["A03:2021"], JS_MEMBER_ASSIGN,
        [p("text_equals", "prop", "innerHTML"), cond("val")],
        "DOM XSS via innerHTML assignment",
        "element.innerHTML = userInput;",
        "element.textContent = userInput;",
    ),
    (
        "JS004", "javascript", "high", [78], ["A03:2021"], JS_CALL_PROP,
        [p("text_equals", "prop", "exec"), p("contains", "arg", "+")],
        "Command injection via exec() with concatenation",
        'cp.exec("ls " + userInput);',
        'cp.exec("ls");',
    ),
    (
        "JS005", "javascript", "high", [89], ["A03:2021"], JS_CALL_PROP,
        [p("text_equals", "prop", "query"), p("contains", "arg", "+")],
        "SQL injection via query() with concatenation",
        'db.query("SELECT * FROM t WHERE id=" + userId);',
        'db.query("SELECT * FROM t WHERE id = 1");',
    ),
    (
        "JS006", "javascript", "high", [798], ["A02:2021"], JS_VAR_STR,
        [p("text_equals", "name", "apiKey")],
        "Hardcoded API key",
        'const apiKey = "sk-live-0123456789";',
        'const apiKey = process.env.API_KEY;',
    ),
    (
        "JS007", "javascript", "high", [502], ["A08:2021"], JS_CALL_PROP_NOARG,
        [p("text_equals", "obj", "yaml"), p("text_equals", "prop", "load")],
        "Unsafe YAML deserialization",
        "yaml.load(userInput);",
        "yaml.safeLoad(userInput);",
    ),
    (
        "JS008", "javascript", "medium", [338], ["A02:2021"], JS_CALL_PROP_NOARG,
        [p("text_equals", "obj", "Math"), p("text_equals", "prop", "random")],
        "Weak randomness for security-sensitive value",
        "const token = Math.random();",
        "const token = crypto.randomUUID();",
    ),
    (
        "JS009", "javascript", "medium", [1004], ["A05:2021"], JS_MEMBER_ASSIGN,
        [p("text_equals", "prop", "cookie"), p("not_contains", "val", "HttpOnly")],
        "Cookie set without HttpOnly",
        "document.cookie = session;",
        'document.cookie = "session=" + id + "; HttpOnly";',
    ),
    (
        "JS010", "javascript", "high", [22], ["A01:2021"], JS_CALL_PROP,
        [p("text_equals", "obj", "fs"), p("text_equals", "prop", "readFile"), cond("arg")],
        "Path traversal via fs.readFile() with user input",
        "fs.readFile(userInput, cb);",
        'fs.readFile("data/fixed.txt", cb);',
    ),
    # ---- TypeScript (TS001-TS005) ----
    (
        "TS001", "typescript", "medium", [704], ["A03:2021"], TS_AS,
        [p("text_equals", "t", "any")],
        "Type safety bypassed with 'as any'",
        "const cmd = (input as any).exec;",
        "const cmd = (input as string).exec;",
    ),
    (
        "TS002", "typescript", "high", [95], ["A03:2021"], JS_CALL_ARG,
        [p("text_equals", "callee", "eval"), cond("arg")],
        "Dynamic code execution via eval() in TypeScript",
        "eval(payload);",
        "render(payload);",
    ),
    (
        "TS003", "typescript", "high", [78], ["A03:2021"], JS_CALL_PROP,
        [p("text_equals", "prop", "exec"), cond("arg")],
        "Command execution with unvalidated argument",
        "cp.exec(userInput);",
        'cp.exec("ls -l");',
    ),
    (
        "TS004", "typescript", "high", [798], ["A02:2021"], JS_VAR_STR,
        [p("text_equals", "name", "secretToken")],
        "Hardcoded secret token",
        'const secretToken = "tok_9f8e7d6c";',
        'const secretToken = loadFromVault("token");',
    ),
    (
        "TS005", "typescript", "high", [79], ["A03:2021"], JS_MEMBER_ASSIGN,
        [p("text_equals", "prop", "innerHTML"), cond("val")],
        "DOM XSS via innerHTML in TypeScript",
        "node.innerHTML = payload;",
        "node.textContent = payload;",
    ),
    # ---- TSX (TS006-TS010) ----
    (
        "TS006", "tsx", "high", [79], ["A03:2021"], TSX_ATTR,
        [p("text_equals", "name", "dangerouslySetInnerHTML")],
        "React dangerouslySetInnerHTML with untrusted markup",
        "<div dangerouslySetInnerHTML={{ __html: html }} />",
        "<div>{html}</div>",
    ),
    (
        "TS007", "tsx", "high", [79], ["A03:2021"], TSX_ATTR_STR,
        [p("text_equals", "name", "href"), p("contains", "val", "javascript:")],
        "javascript: URL in JSX attribute",
        '<a href="javascript:alert(1)">x</a>',
        '<a href="https://example.com">x</a>',
    ),
    (
        "TS008", "tsx", "high", [95], ["A03:2021"], JS_CALL_ARG,
        [p("text_equals", "callee", "eval"), cond("arg")],
        "Dynamic code execution via eval() in TSX",
        "eval(payload);",
        "render(payload);",
    ),
    (
        "TS009", "tsx", "medium", [1021], ["A04:2021"], TSX_ATTR_STR,
        [p("text_equals", "name", "target"), p("contains", "val", "_blank")],
        "target=_blank without rel=noopener",
        '<a target="_blank" href="x">x</a>',
        '<a href="x">x</a>',
    ),
    (
        "TS010", "tsx", "high", [79], ["A03:2021"], TSX_ATTR,
        [p("text_equals", "name", "onClick")],
        "Inline handler attribute receives raw payload",
        "<button onClick={handler} />",
        "<button type=\"button\" />",
    ),
    # ---- Python (PY001-PY010) ----
    (
        "PY001", "python", "high", [95], ["A03:2021"], PY_CALL,
        [p("text_equals", "callee", "eval"), cond("arg")],
        "Dynamic code execution via eval()",
        "eval(user_input)",
        "compute(user_input)",
    ),
    (
        "PY002", "python", "high", [95], ["A03:2021"], PY_CALL,
        [p("text_equals", "callee", "exec"), cond("arg")],
        "Dynamic code execution via exec()",
        "exec(user_input)",
        "run(user_input)",
    ),
    (
        "PY003", "python", "high", [502], ["A08:2021"], PY_METHOD,
        [p("text_equals", "obj", "pickle"), p("text_equals", "prop", "loads")],
        "Unsafe pickle deserialization",
        "pickle.loads(data)",
        "json.loads(data)",
    ),
    (
        "PY004", "python", "high", [502], ["A08:2021"], PY_METHOD,
        [p("text_equals", "obj", "yaml"), p("text_equals", "prop", "load")],
        "Unsafe YAML deserialization",
        "yaml.load(stream)",
        "yaml.safe_load(stream)",
    ),
    (
        "PY005", "python", "high", [78], ["A03:2021"], PY_KWARG_TRUE,
        [p("text_equals", "kw", "shell")],
        "Command injection via shell=True",
        "subprocess.run(cmd, shell=True)",
        "subprocess.run(cmd, shell=False)",
    ),
    (
        "PY006", "python", "high", [89], ["A03:2021"], PY_METHOD,
        [p("text_equals", "prop", "execute"), p("contains", "arg", "+")],
        "SQL injection via string concatenation",
        'cur.execute("SELECT * FROM t WHERE id=" + uid)',
        'cur.execute("SELECT * FROM t WHERE id = 1")',
    ),
    (
        "PY007", "python", "high", [798], ["A02:2021"], PY_ASSIGN_STR,
        [p("text_equals", "name", "api_key"), p("has_prefix", "val", QUOTE)],
        "Hardcoded API key",
        'api_key = "sk-live-0123456789"',
        'api_key = os.environ["API_KEY"]',
    ),
    (
        "PY008", "python", "medium", [295], ["A02:2021"], PY_KWARG_FALSE,
        [p("text_equals", "kw", "verify")],
        "TLS verification disabled",
        "requests.get(url, verify=False)",
        "requests.get(url, verify=True)",
    ),
    (
        "PY009", "python", "medium", [328], ["A02:2021"], PY_METHOD_NAME,
        [p("text_equals", "prop", "md5")],
        "Weak hash algorithm (MD5)",
        "hashlib.md5(data)",
        "hashlib.sha256(data)",
    ),
    (
        "PY010", "python", "low", [617], ["A04:2021"], "(assert_statement) @stmt",
        [],
        "assert used for security check (stripped with -O)",
        "assert user.is_admin",
        "if not user.is_admin:\n    raise PermissionError()",
    ),
    # ---- Java (JAVA001-JAVA010) ----
    (
        "JAVA001", "java", "high", [78], ["A03:2021"], JAVA_CALL,
        [p("text_equals", "name", "exec"), cond("arg")],
        "Command injection via Runtime.exec()",
        'Runtime.getRuntime().exec(input);',
        'Runtime.getRuntime().exec("ls -l");',
    ),
    (
        "JAVA002", "java", "high", [89], ["A03:2021"], JAVA_CALL,
        [p("text_equals", "name", "executeQuery"), p("contains", "arg", "+")],
        "SQL injection via concatenated query",
        'stmt.executeQuery("SELECT * FROM t WHERE id=" + id);',
        'stmt.executeQuery("SELECT * FROM t WHERE id = 1");',
    ),
    (
        "JAVA003", "java", "high", [798], ["A02:2021"], JAVA_LOCAL_STR,
        [p("text_equals", "name", "password")],
        "Hardcoded password",
        'String password = "hunter2";',
        'String password = System.getenv("PASSWORD");',
    ),
    (
        "JAVA004", "java", "high", [611], ["A05:2021"], JAVA_NEW,
        [p("text_equals", "t", "DocumentBuilderFactory")],
        "XXE-prone XML parser factory",
        "DocumentBuilderFactory dbf = new DocumentBuilderFactory(null);",
        "SAXParserFactory spf = new SAXParserFactory(null);",
    ),
    (
        "JAVA005", "java", "high", [502], ["A08:2021"], JAVA_NEW,
        [p("text_equals", "t", "ObjectInputStream")],
        "Java deserialization of untrusted data",
        "new ObjectInputStream(input);",
        "new DataInputStream(input);",
    ),
    (
        "JAVA006", "java", "medium", [338], ["A02:2021"], JAVA_NEW,
        [p("text_equals", "t", "Random")],
        "Predictable random generator for tokens",
        "new Random(seed);",
        "new SecureRandom(seed);",
    ),
    (
        "JAVA007", "java", "medium", [22], ["A01:2021"], JAVA_NEW,
        [p("text_equals", "t", "File"), cond("arg")],
        "File handle built from unvalidated path",
        'new File(userInput);',
        'new File("/srv/data/fixed.txt");',
    ),
    (
        "JAVA008", "java", "medium", [532], ["A09:2021"], JAVA_CALL,
        [p("text_equals", "name", "info"), p("contains", "arg", "password")],
        "Sensitive value written to log",
        'log.info("login password=" + password);',
        'log.info("login ok");',
    ),
    (
        "JAVA009", "java", "medium", [327], ["A02:2021"], JAVA_CALL,
        [p("text_equals", "name", "getInstance"), p("contains", "arg", "DES")],
        "Weak cipher algorithm (DES)",
        'Cipher.getInstance("DES/ECB/PKCS5Padding");',
        'Cipher.getInstance("AES/GCM/NoPadding");',
    ),
    (
        "JAVA010", "java", "low", [209], ["A09:2021"], JAVA_CALL_PLAIN,
        [p("text_equals", "name", "printStackTrace")],
        "Stack trace printed instead of handled",
        "e.printStackTrace();",
        'log.error("failed", e);',
    ),
    # ---- JSON configuration (CFG001-CFG010) ----
    (
        "CFG001", "json", "high", [798], ["A02:2021"], JSON_PAIR_STR,
        [p("contains", "key", "password")],
        "Plaintext password in configuration",
        '{\n  "password": "hunter2",\n  "name": "svc"\n}',
        '{\n  "username": "svc",\n  "name": "svc"\n}',
    ),
    (
        "CFG002", "json", "medium", [489], ["A05:2021"], JSON_PAIR_TRUE,
        [p("contains", "key", "debug")],
        "Debug mode enabled in configuration",
        '{\n  "debug": true,\n  "name": "svc"\n}',
        '{\n  "debug": false,\n  "name": "svc"\n}',
    ),
    (
        "CFG003", "json", "high", [942], ["A05:2021"], JSON_PAIR_STR,
        [p("contains", "key", "Origin"), p("contains", "val", "*")],
        "Permissive CORS origin",
        '{\n  "allowedOrigin": "*",\n  "name": "svc"\n}',
        '{\n  "allowedOrigin": "https://app.example.com",\n  "name": "svc"\n}',
    ),
    (
        "CFG004", "json", "high", [319], ["A02:2021"], JSON_PAIR_FALSE,
        [p("contains", "key", "tls")],
        "TLS verification disabled in configuration",
        '{\n  "tlsVerify": false,\n  "name": "svc"\n}',
        '{\n  "tlsVerify": true,\n  "name": "svc"\n}',
    ),
    (
        "CFG005", "json", "medium", [732], ["A01:2021"], JSON_PAIR_STR,
        [p("contains", "key", "permission"), p("contains", "val", "*")],
        "Wildcard permission grant",
        '{\n  "permissions": "*",\n  "name": "svc"\n}',
        '{\n  "permissions": "read",\n  "name": "svc"\n}',
    ),
    (
        "CFG006", "json", "high", [798], ["A02:2021"], JSON_PAIR_STR,
        [p("contains", "key", "token")],
        "Hardcoded token in configuration",
        '{\n  "api_token": "tok_9f8e7d6c",\n  "name": "svc"\n}',
        '{\n  "authRef": "vault:svc/token",\n  "name": "svc"\n}',
    ),
    (
        "CFG007", "json", "high", [942], ["A05:2021"], JSON_PAIR_STR,
        [p("contains", "key", "host"), p("contains", "val", "*")],
        "Wildcard host binding",
        '{\n  "allowed_host": "*",\n  "name": "svc"\n}',
        '{\n  "allowed_host": "app.example.com",\n  "name": "svc"\n}',
    ),
    (
        "CFG008", "json", "high", [295], ["A02:2021"], JSON_PAIR_FALSE,
        [p("contains", "key", "verify")],
        "Verification disabled in configuration",
        '{\n  "verifySsl": false,\n  "name": "svc"\n}',
        '{\n  "verifySsl": true,\n  "name": "svc"\n}',
    ),
    (
        "CFG009", "json", "medium", [327], ["A02:2021"], JSON_PAIR_STR,
        [p("contains", "key", "cipher"), p("contains", "val", "RC4")],
        "Weak cipher suite enabled",
        '{\n  "cipherSuite": "RC4-SHA",\n  "name": "svc"\n}',
        '{\n  "cipherSuite": "TLS_AES_256_GCM_SHA384",\n  "name": "svc"\n}',
    ),
    (
        "CFG010", "json", "high", [522], ["A05:2021"], JSON_PAIR_STR,
        [p("contains", "key", "secret")],
        "Secret material stored in plaintext configuration",
        '{\n  "client_secret": "s3cr3t-value",\n  "name": "svc"\n}',
        '{\n  "vaultRef": "vault:svc/credential",\n  "name": "svc"\n}',
    ),
    # ---- MoonBit (MB001-MB010): first-batch rules from the P4 spike ----
    (
        "MB001", "moonbit", "high", [78], ["A03:2021"], MB_CALL_PKG,
        [p("text_equals", "pkg", "@process"), p("text_equals", "fn", ".run"),
         p("not_has_prefix", "arg", QUOTE)],
        "Command injection: process.run with untrusted command",
        'fn main {\n  @process.run(cmd, args)\n}\n',
        'fn main {\n  @process.run("ls", args)\n}\n',
    ),
    (
        "MB002", "moonbit", "high", [22], ["A01:2021"], MB_CALL_PKG,
        [p("text_equals", "pkg", "@fs"), p("text_equals", "fn", ".read_file")],
        "Path traversal: fs.read_file with untrusted path",
        'fn main {\n  let d = @fs.read_file(path)\n}\n',
        'fn main {\n  let d = @fs.write_file(path, data)\n}\n',
    ),
    (
        "MB003", "moonbit", "high", [798], ["A07:2021"], MB_CONST_STR,
        [p("contains", "name", "KEY"), p("has_prefix", "str", '"sk_')],
        "Hardcoded API key in const definition",
        'const API_KEY : String = "sk_live_1234567890"\n',
        'const API_KEY : String = "production"\n',
    ),
    (
        "MB004", "moonbit", "medium", [328], ["A02:2021"], MB_CALL_PKG,
        [p("text_equals", "pkg", "@crypto"), p("text_equals", "fn", ".md5")],
        "Weak hash: crypto.md5",
        'fn main {\n  let h = @crypto.md5(data)\n}\n',
        'fn main {\n  let h = @crypto.sha256(data)\n}\n',
    ),
    (
        "MB005", "moonbit", "medium", [338], ["A02:2021"], MB_RAND_METHOD,
        [p("text_equals", "pkg", "@random"), p("text_equals", "ty", ".Rand"),
         p("text_equals", "fn", "new")],
        "Weak RNG: Rand::new() (use Rand::chacha8 for tokens)",
        'fn main {\n  let r = @random.Rand::new()\n}\n',
        'fn main {\n  let r = @random.Rand::chacha8()\n}\n',
    ),
    (
        "MB006", "moonbit", "high", [295], ["A02:2021"], MB_TLS_VERIFY,
        [p("text_equals", "pkg", "@tls"), p("text_equals", "label", "verify"),
         p("text_equals", "val", "false")],
        "TLS verification disabled: verify=false",
        'fn main {\n  let t = @tls.Tls::client(inner, verify=false)\n}\n',
        'fn main {\n  let t = @tls.Tls::client(inner, verify=true)\n}\n',
    ),
    (
        "MB007", "moonbit", "medium", [532], ["A09:2021"], MB_ENV_LOG,
        [p("text_equals", "fn", "println"), p("text_equals", "pkg", "@env"),
         p("text_equals", "getter", ".get_env_var")],
        "Sensitive env value written to log",
        'fn main {\n  println(@env.get_env_var("TOKEN"))\n}\n',
        'fn main {\n  println("constant")\n}\n',
    ),
    (
        "MB008", "moonbit", "medium", [1116], ["A06:2021"], MB_EXTERN,
        [p("contains", "lib", '"C"')],
        "FFI boundary: external C linkage",
        'extern "C"\nfn c_func() -> Int\n',
        'fn pure_fn() -> Int {\n  42\n}\n',
    ),
    (
        "MB009", "moonbit", "medium", [327], ["A02:2021"], MB_HMAC,
        [p("text_equals", "pkg", "@crypto"), p("text_equals", "fn", ".hmac"),
         p("text_equals", "label", "digest"), p("text_equals", "alg", "MD5")],
        "Weak HMAC digest: MD5",
        'fn main {\n  let m = @crypto.hmac(data, key, digest=MD5)\n}\n',
        'fn main {\n  let m = @crypto.hmac(data, key, digest=SHA256)\n}\n',
    ),
    (
        "MB010", "moonbit", "low", [390], ["A09:2021"], MB_EMPTY_CATCH,
        [],
        "Exception swallowed by empty catch",
        'fn main {\n  try { risky() } catch { }\n}\n',
        'fn main {\n  try { risky() } catch { e => println(e) }\n}\n',
    ),
]

EXT = {
    "javascript": "js",
    "typescript": "ts",
    "tsx": "tsx",
    "python": "py",
    "java": "java",
    "json": "json",
    "moonbit": "mb",
}

# MoonBit snippets are already complete source files; only two put the
# offending node on line 1 instead of line 2.
MB_POSITIVE_LINES = {"MB003": 1, "MB008": 1}


def wrap(language: str, body: str) -> str:
    """Wrap a vulnerable/safe snippet into a compilable file."""
    if language == "java":
        return "class Probe {\n  void run(String input, String userInput, String payload) { %s }\n}\n" % body
    return body if body.endswith("\n") else body + "\n"


def rule_json(entry) -> dict:
    rid, lang, sev, cwe, owasp, query, preds, msg, _pos, _neg = entry
    return {
        "id": rid,
        "language": lang,
        "severity": sev,
        "cwe": cwe,
        "owasp": owasp,
        "query": query,
        "predicates": preds,
        "message": msg,
        "enabled": True,
    }


def build():
    rules = [rule_json(e) for e in RULES]
    files = {}
    files[PACK / "rules.json"] = json.dumps(rules, indent=2, ensure_ascii=False) + "\n"
    sha = hashlib.sha256(files[PACK / "rules.json"].encode()).hexdigest()
    manifest = {
        "name": "official",
        "version": "1.0.0",
        "analyzer_min_version": "0.1.0",
        "rules_file": "rules.json",
        "rules_sha256": sha,
    }
    # S4b-5: the optional taint manifest is declared and checksummed here too,
    # keeping the generator as the single source of truth for manifest.json.
    taint_path = PACK / "taint.json"
    if taint_path.exists():
        manifest["taint_file"] = "taint.json"
        manifest["taint_sha256"] = hashlib.sha256(taint_path.read_bytes()).hexdigest()
    files[PACK / "manifest.json"] = json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"
    for entry in RULES:
        rid, lang, _sev, _cwe, _owasp, _q, _preds, _msg, pos, neg = entry
        ext = EXT[lang]
        base = FIXTURES / rid
        files[base / ("positive." + ext)] = wrap(lang, pos)
        files[base / ("negative." + ext)] = wrap(lang, neg)
        first_line = MB_POSITIVE_LINES.get(
            rid, 2 if lang in ("java", "json", "moonbit") else 1
        )
        expected = {
            "rule_id": rid,
            "positive_findings": 1,
            "negative_findings": 0,
            "positive_lines": [first_line],
        }
        files[base / "expected.json"] = json.dumps(expected, indent=2) + "\n"
    return files


def main() -> int:
    files = build()
    if "--check" in sys.argv:
        stale = []
        for path, content in files.items():
            if not path.exists() or path.read_bytes() != content.encode("utf-8"):
                stale.append(path)
        if stale:
            for path in stale:
                print("stale:", path.relative_to(ROOT))
            return 1
        print("rulepack is up to date")
        return 0
    for path, content in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        # Binary write: Windows text mode would turn "\n" into "\r\n" and break
        # the manifest checksum, which is computed over the exact bytes.
        path.write_bytes(content.encode("utf-8"))
    print("wrote %d files (%d rules)" % (len(files), len(RULES)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
