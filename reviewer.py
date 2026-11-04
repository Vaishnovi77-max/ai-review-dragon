from __future__ import annotations

import ast
import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass

SEVERITY_RANK = {"critical": 0, "warning": 1, "info": 2}


@dataclass
class Issue:
    line: int
    severity: str
    category: str
    message: str
    suggestion: str
    snippet: str = ""


@dataclass(frozen=True)
class PatternRule:
    rule_id: str
    severity: str
    category: str
    language: str
    pattern: re.Pattern
    message: str
    suggestion: str
    ast_covered: bool = False


def _rule(rule_id, severity, category, language, pattern, message, suggestion, ast_covered=False):
    return PatternRule(rule_id, severity, category, language, re.compile(pattern), message, suggestion, ast_covered)


PATTERN_RULES = [
    # JavaScript / TypeScript
    _rule("loose-eq", "warning", "Correctness", "javascript", r"(^|[^=!<>])==([^=]|$)",
          "Loose equality (==) performs type coercion and can hide bugs.",
          "Use strict equality (===) or strict inequality (!==)."),
    _rule("loose-neq", "warning", "Correctness", "javascript", r"(^|[^!<>])!=([^=]|$)",
          "Loose inequality (!=) performs type coercion and can hide bugs.",
          "Use strict inequality (!==)."),
    _rule("eval-js", "critical", "Security", "javascript", r"\beval\s*\(",
          "eval() executes arbitrary code and is a major injection risk.",
          "Remove eval and use JSON.parse, a safe parser, or explicit logic."),
    _rule("innerhtml", "warning", "Security", "javascript", r"\.innerHTML\s*=",
          "Assigning untrusted data to innerHTML can introduce XSS.",
          "Use textContent, or sanitize the value with a library such as DOMPurify."),
    _rule("document-write", "warning", "Security", "javascript", r"document\.write\s*\(",
          "document.write() can clobber the page and enables injection.",
          "Create and append DOM nodes instead."),
    _rule("settimeout-string", "warning", "Security", "javascript", r"setTimeout\s*\(\s*[\"']",
          "A string passed to setTimeout is evaluated like code.",
          "Pass a function reference instead of a string."),
    _rule("debugger", "warning", "Debug", "javascript", r"\bdebugger\b",
          "A debugger statement is left in the code.",
          "Remove it before shipping."),
    _rule("console-log", "info", "Debug", "javascript", r"console\.(log|debug)\s*\(",
          "Debug logging is left in the code.",
          "Remove it or route it through a logger that can be disabled."),
    _rule("var", "info", "Style", "javascript", r"\bvar\s+[A-Za-z_$]",
          "var is function-scoped and hoisted.",
          "Prefer let or const for predictable block scoping."),
    _rule("empty-catch", "warning", "Error handling", "javascript", r"catch\s*(\([^)]*\))?\s*\{\s*\}",
          "An empty catch block silently swallows the error.",
          "Log the error, rethrow it, or handle the failure explicitly."),

    # Go
    _rule("panic", "warning", "Reliability", "go", r"\bpanic\s*\(",
          "panic unwinds the goroutine and can crash the program.",
          "Return an error instead, or reserve panic for unrecoverable states."),
    _rule("go-print", "info", "Debug", "go", r"\bfmt\.Print(f|ln)?\s*\(",
          "Debug printing is left in the code.",
          "Use a structured logger (slog/log) instead."),
    _rule("ignored-error", "warning", "Error handling", "go", r"_\s*=\s*[\w.]+\s*\(",
          "A returned error is discarded.",
          "Handle the error, or explicitly document why it is safe to ignore."),
    _rule("log-fatal", "info", "Reliability", "go", r"\blog\.Fatal",
          "log.Fatal exits the process immediately and skips deferred cleanup.",
          "Return the error to main and exit there."),

    # Python fallback rules (only used when the file cannot be parsed)
    _rule("eval-py", "critical", "Security", "python", r"\b(eval|exec)\s*\(",
          "eval/exec executes arbitrary code and is a major injection risk.",
          "Use a safe parser (ast.literal_eval) or explicit logic instead."),
    _rule("os-system", "critical", "Security", "python", r"\bos\.(system|popen)\s*\(",
          "os.system() passes input to a shell and enables command injection.",
          "Use subprocess.run with a list of arguments and shell=False."),
    _rule("pickle-py", "critical", "Security", "python", r"\b(pickle|cPickle)\.loads?\s*\(",
          "Deserializing untrusted pickle data can execute arbitrary code.",
          "Use JSON or another safe format for untrusted input."),
    _rule("bare-except-py", "warning", "Error handling", "python", r"except\s*:",
          "A bare except catches everything, including SystemExit and KeyboardInterrupt.",
          "Catch specific exception types, or at least use Exception."),
    _rule("print-py", "info", "Debug", "python", r"\bprint\s*\(",
          "Debug printing is left in the code.",
          "Use the logging module so output can be controlled."),
    _rule("eq-none-py", "info", "Correctness", "python", r"==\s*None",
          "Comparing to None with == can call overloaded equality.",
          "Use 'is None' / 'is not None'."),

    # Language-agnostic
    _rule("hardcoded-secret", "critical", "Security", "",
          r"(?i)(password|passwd|pwd|secret|api[_-]?key|token|access[_-]?key)\s*[:=]\s*[\"'][^\"']{4,}[\"']",
          "A possible hard-coded credential is committed in the source.",
          "Move secrets to environment variables or a secret manager, and rotate the exposed value."),
    _rule("sql-injection", "critical", "Security", "",
          r"(?i)(select|insert|update|delete)\b.*(\+\s*\w|%s|%d|\$\{)",
          "A SQL query appears to be built with concatenation or string interpolation.",
          "Use parameterized queries / prepared statements.", True),
    _rule("todo", "info", "Maintenance", "", r"\b(TODO|FIXME|XXX|HACK)\b",
          "A TODO/FIXME marker is left in the code.",
          "Track it in an issue, or resolve it before merging."),
]


def normalize_language(language: str, filename: str) -> str:
    lang = (language or "").strip().lower()
    aliases = {
        "js": "javascript", "jsx": "javascript", "ts": "javascript",
        "tsx": "javascript", "typescript": "javascript",
        "py": "python", "golang": "go",
    }
    if lang in aliases:
        return aliases[lang]
    if lang:
        return lang

    name = (filename or "").lower()
    if name.endswith((".js", ".jsx", ".ts", ".tsx")):
        return "javascript"
    if name.endswith(".py"):
        return "python"
    if name.endswith(".go"):
        return "go"
    return ""


def _snippet(line: str) -> str:
    text = line.strip()
    return text[:157] + "..." if len(text) > 160 else text


def _dotted(node: ast.AST) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


def _is_mutable_default(node: ast.AST) -> bool:
    return isinstance(node, (ast.List, ast.Dict, ast.Set, ast.ListComp, ast.DictComp, ast.SetComp))


def _cyclomatic(function: ast.AST) -> int:
    score = 1
    stack = list(getattr(function, "body", []))
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            continue
        if isinstance(node, (ast.If, ast.For, ast.AsyncFor, ast.While,
                             ast.ExceptHandler, ast.BoolOp, ast.IfExp)):
            score += 1
        stack.extend(ast.iter_child_nodes(node))
    return score


class PythonAnalyzer(ast.NodeVisitor):
    def __init__(self, code: str, filename: str):
        self.lines = code.split("\n")
        self.filename = filename
        self.issues: list[Issue] = []
        self.used: set[str] = set()
        self.imports: list[tuple[str, int]] = []
        self._seen: set[tuple] = set()

    def add(self, line: int, severity: str, category: str, message: str, suggestion: str) -> None:
        line = max(1, line)
        key = (line, severity, category, message)
        if key in self._seen:
            return
        self._seen.add(key)
        text = self.lines[line - 1] if line <= len(self.lines) else ""
        self.issues.append(Issue(line, severity, category, message, suggestion, _snippet(text)))

    def add_node(self, node: ast.AST, severity: str, category: str, message: str, suggestion: str) -> None:
        self.add(getattr(node, "lineno", 1) or 1, severity, category, message, suggestion)

    def visit_Call(self, node: ast.Call) -> None:
        name = _dotted(node.func)

        if name in ("eval", "exec", "builtins.eval", "builtins.exec"):
            self.add_node(node, "critical", "Security",
                          "eval/exec executes arbitrary code and is a major injection risk.",
                          "Use ast.literal_eval or explicit logic instead.")
        if name in ("os.system", "os.popen"):
            self.add_node(node, "critical", "Security",
                          f"{name}() passes input to a shell and enables command injection.",
                          "Use subprocess.run with a list of arguments and shell=False.")
        if name in ("pickle.load", "pickle.loads", "cPickle.load", "cPickle.loads", "marshal.loads"):
            self.add_node(node, "critical", "Security",
                          f"{name}() on untrusted data can execute arbitrary code.",
                          "Use JSON or another safe format for untrusted input.")
        if name == "yaml.load":
            safe = any(
                kw.arg == "Loader" and "safe" in _dotted(kw.value).lower()
                for kw in node.keywords
            )
            if not safe:
                self.add_node(node, "warning", "Security",
                              "yaml.load() without a safe Loader can execute arbitrary objects.",
                              "Use yaml.safe_load() or pass Loader=yaml.SafeLoader.")
        if name in ("hashlib.md5", "hashlib.sha1"):
            self.add_node(node, "warning", "Security",
                          f"{name}() is cryptographically weak.",
                          "Use SHA-256 or better, and a password hashing algorithm for credentials.")
        if name.startswith("subprocess."):
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self.add_node(node, "critical", "Security",
                                  "subprocess is called with shell=True and may allow command injection.",
                                  "Pass an argument list and keep shell=False.")
                    break
        if name == "tempfile.mktemp":
            self.add_node(node, "warning", "Security",
                          "tempfile.mktemp() is vulnerable to race conditions.",
                          "Use tempfile.NamedTemporaryFile() or mkstemp().")
        if name.startswith("requests."):
            for kw in node.keywords:
                if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                    self.add_node(node, "critical", "Security",
                                  "TLS certificate verification is disabled.",
                                  "Remove verify=False and fix the underlying certificate issue.")
                    break
        if name in ("print",):
            self.add_node(node, "info", "Debug",
                          "Debug printing is left in the code.",
                          "Use the logging module so output can be controlled.")
        if name == "breakpoint":
            self.add_node(node, "warning", "Debug",
                          "A breakpoint() call is left in the code.",
                          "Remove it before shipping.")
        if name in ("exit", "quit"):
            self.add_node(node, "info", "Reliability",
                          f"{name}() is intended for interactive use, not library code.",
                          "Raise SystemExit or return an error instead.")

        if name.endswith((".execute", ".executemany")) or name in ("execute", "executemany"):
            for arg in node.args:
                risky = (
                    isinstance(arg, ast.JoinedStr)
                    or (isinstance(arg, ast.BinOp) and isinstance(arg.op, (ast.Add, ast.Mod)))
                    or (isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute)
                        and arg.func.attr == "format")
                )
                if risky:
                    self.add_node(node, "critical", "Security",
                                  "A SQL query is built with concatenation or string interpolation.",
                                  "Use parameterized queries / prepared statements.")
                    break

        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.type is None:
            self.add_node(node, "warning", "Error handling",
                          "A bare except catches everything, including SystemExit and KeyboardInterrupt.",
                          "Catch specific exception types, or at least use Exception.")
        if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
            self.add_node(node, "warning", "Error handling",
                          "The exception is swallowed with pass.",
                          "Log the error, rethrow it, or handle the failure explicitly.")
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        operands = [node.left] + list(node.comparators)
        for op, right in zip(node.ops, node.comparators):
            if isinstance(op, (ast.Eq, ast.NotEq)) and isinstance(right, ast.Constant) and right.value is None:
                self.add_node(node, "info", "Correctness",
                              "Comparing to None with == can call overloaded equality.",
                              "Use 'is None' / 'is not None'.")
        for op, left in zip(node.ops, operands[:-1]):
            if isinstance(op, (ast.Eq, ast.NotEq)) and isinstance(left, ast.Constant) and left.value is None:
                self.add_node(node, "info", "Correctness",
                              "Comparing to None with == can call overloaded equality.",
                              "Use 'is None' / 'is not None'.")
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            name = alias.asname or alias.name.split(".")[0]
            self.imports.append((name, node.lineno))

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module == "__future__":
            return
        for alias in node.names:
            if alias.name == "*":
                self.add_node(node, "warning", "Style",
                              "Wildcard imports pollute the namespace and hide dependencies.",
                              "Import only the names you use.")
                continue
            self.imports.append((alias.asname or alias.name, node.lineno))

    def visit_Name(self, node: ast.Name) -> None:
        self.used.add(node.id)

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == "__all__":
                if isinstance(node.value, (ast.List, ast.Tuple)):
                    for elt in node.value.elts:
                        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                            self.used.add(elt.value)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._check_function(node)

    def _check_function(self, node) -> None:
        defaults = [d for d in list(node.args.defaults) + list(node.args.kw_defaults) if d is not None]
        for default in defaults:
            if _is_mutable_default(default):
                self.add_node(node, "warning", "Correctness",
                              f"Mutable default argument in '{node.name}' is shared between calls.",
                              "Use None as the default and create the object inside the function.")

        arg_count = len(node.args.posonlyargs) + len(node.args.args) + len(node.args.kwonlyargs)
        if arg_count > 6:
            self.add_node(node, "info", "Maintainability",
                          f"Function '{node.name}' takes {arg_count} arguments.",
                          "Group related arguments into a dataclass or config object.")

        complexity = _cyclomatic(node)
        if complexity > 10:
            self.add_node(node, "info", "Maintainability",
                          f"Function '{node.name}' has cyclomatic complexity {complexity}.",
                          "Split it into smaller functions and simplify branching.")

        end = getattr(node, "end_lineno", node.lineno) or node.lineno
        length = end - node.lineno + 1
        if length > 80:
            self.add_node(node, "info", "Style",
                          f"Function '{node.name}' is {length} lines long.",
                          "Extract helper functions to keep it readable.")

        self.generic_visit(node)

    def visit_Global(self, node: ast.Global) -> None:
        for name in node.names:
            self.add_node(node, "warning", "Maintainability",
                          f"Global variable '{name}' is modified in this scope.",
                          "Pass state explicitly or encapsulate it in a class.")

    def visit_Assert(self, node: ast.Assert) -> None:
        self.add_node(node, "info", "Reliability",
                      "assert statements are removed when Python runs with -O.",
                      "Use an explicit check and raise an exception for validation.")
        self.generic_visit(node)

    def visit_Dict(self, node: ast.Dict) -> None:
        seen = {}
        for key in node.keys:
            if isinstance(key, ast.Constant) and isinstance(key.value, (str, int, float, bool)):
                marker = (type(key.value).__name__, key.value)
                if marker in seen:
                    self.add_node(node, "warning", "Correctness",
                                  f"Duplicate dictionary key {key.value!r}; the later value overwrites the earlier one.",
                                  "Remove the duplicate key or use a different structure.")
                else:
                    seen[marker] = key
        self.generic_visit(node)

    def finish(self) -> None:
        if os.path.basename(self.filename) == "__init__.py":
            return
        for name, line in self.imports:
            if name not in self.used and name != "annotations":
                self.add(line, "info", "Style",
                         f"Imported name '{name}' is never used.",
                         "Remove the unused import.")


def analyze_python(code: str, filename: str) -> tuple[list[Issue], bool]:
    try:
        tree = ast.parse(code, filename=filename or "<code>")
    except SyntaxError as exc:
        line = exc.lineno or 1
        lines = code.split("\n")
        text = lines[line - 1] if line <= len(lines) else ""
        issue = Issue(
            line=line,
            severity="critical",
            category="Syntax",
            message=f"Could not parse the file: {exc.msg}.",
            suggestion="Fix the syntax error first; static analysis was skipped.",
            snippet=_snippet(text),
        )
        return [issue], False

    analyzer = PythonAnalyzer(code, filename)
    analyzer.visit(tree)
    analyzer.finish()
    return analyzer.issues, True


def analyze_patterns(language: str, code: str, python_ast_ok: bool) -> list[Issue]:
    lines = code.split("\n")
    issues: list[Issue] = []
    seen: set[tuple] = set()

    def add(line_no: int, severity: str, category: str, message: str, suggestion: str) -> None:
        key = (line_no, severity, category, message)
        if key in seen:
            return
        seen.add(key)
        text = lines[line_no - 1] if line_no <= len(lines) else ""
        issues.append(Issue(line_no, severity, category, message, suggestion, _snippet(text)))

    for index, line in enumerate(lines, start=1):
        for rule in PATTERN_RULES:
            if rule.language and rule.language != language:
                continue
            if language == "python" and python_ast_ok and (rule.language == "python" or rule.ast_covered):
                continue
            if not rule.pattern.search(line):
                continue
            add(index, rule.severity, rule.category, rule.message, rule.suggestion)

        if len(line) > 120 and line.strip():
            add(index, "info", "Style",
                f"Line is {len(line)} characters long (limit 120).",
                "Wrap the line to keep the code readable.")

    return issues


def ai_enabled() -> bool:
    return bool(os.environ.get("REVIEWAI_API_KEY"))


def _ai_prompt(code: str, filename: str, language: str) -> tuple[str, str]:
    system = (
        "You are a senior software engineer doing a focused code review. "
        "Report only concrete, line-specific issues in bugs, security, or style. "
        "Return ONLY a JSON object with this exact shape: "
        '{"issues":[{"line":1,"severity":"critical|warning|info","category":"Security",'
        '"message":"what is wrong","suggestion":"how to fix it"}]}. '
        "line is 1-based, messages must stay under 200 characters."
    )
    user = (
        f"Filename: {filename}\nLanguage: {language}\n\n"
        f"```{language}\n{code}\n```"
    )
    return system, user


def analyze_with_ai(code: str, filename: str, language: str) -> list[Issue]:
    base = os.environ.get("REVIEWAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    model = os.environ.get("REVIEWAI_MODEL", "gpt-4o-mini")
    system, user = _ai_prompt(code, filename, language)

    payload = json.dumps({
        "model": model,
        "temperature": 0.2,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }).encode("utf-8")

    request = urllib.request.Request(
        base + "/chat/completions",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + os.environ.get("REVIEWAI_API_KEY", ""),
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            raw = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"LLM returned {exc.code}: {body[:300]}") from exc

    data = json.loads(raw)
    content = data["choices"][0]["message"]["content"].strip()
    if "{" in content:
        content = content[content.index("{"):]
    if "}" in content:
        content = content[:content.rindex("}") + 1]

    parsed = json.loads(content)
    lines = code.split("\n")
    issues: list[Issue] = []
    for item in parsed.get("issues", []):
        if not isinstance(item, dict):
            continue
        severity = str(item.get("severity", "warning")).strip().lower()
        if severity in {"critical", "high", "blocker"}:
            severity = "critical"
        elif severity in {"info", "low", "minor", "suggestion", "nit"}:
            severity = "info"
        else:
            severity = "warning"

        message = str(item.get("message", "")).strip()
        if not message:
            continue
        try:
            line = int(item.get("line", 1))
        except (TypeError, ValueError):
            line = 1
        line = min(max(1, line), len(lines))
        snippet = str(item.get("snippet", "")).strip() or _snippet(lines[line - 1])
        category = str(item.get("category", "")).strip() or "General"
        suggestion = str(item.get("suggestion", "")).strip() or "Review this line."
        issues.append(Issue(line, severity, category, message, suggestion, snippet))
    return issues


def _merge(primary: list[Issue], secondary: list[Issue]) -> list[Issue]:
    seen: set[tuple] = set()
    merged: list[Issue] = []
    for issue in list(primary) + list(secondary):
        key = (issue.line, issue.severity, issue.category.lower())
        if key in seen:
            continue
        seen.add(key)
        merged.append(issue)
    return merged


def _sort(issues: list[Issue]) -> list[Issue]:
    return sorted(issues, key=lambda i: (i.line, SEVERITY_RANK.get(i.severity, 3)))


def _score(code: str, issues: list[Issue]) -> tuple[int, dict]:
    lines = code.split("\n")
    metrics = {
        "lines": len(lines),
        "codeLines": sum(1 for line in lines if line.strip()),
        "issues": len(issues),
        "critical": 0,
        "warnings": 0,
        "infos": 0,
    }
    score = 100
    for issue in issues:
        if issue.severity == "critical":
            metrics["critical"] += 1
            score -= 15
        elif issue.severity == "warning":
            metrics["warnings"] += 1
            score -= 6
        else:
            metrics["infos"] += 1
            score -= 2
    return max(0, score), metrics


def _summary(metrics: dict) -> str:
    critical = metrics["critical"]
    warnings = metrics["warnings"]
    infos = metrics["infos"]
    if critical:
        return (f"Found {critical} critical issue(s), {warnings} warning(s) and "
                f"{infos} suggestion(s). Resolve the critical items before merging.")
    if warnings:
        return f"No critical issues. Found {warnings} warning(s) and {infos} suggestion(s) worth cleaning up."
    if infos:
        return f"No blocking issues. Found {infos} minor suggestion(s) for polish."
    return "No issues detected. This code looks clean — nice work."


def review_code(code: str, filename: str = "", language: str = "", use_ai: bool | None = None) -> dict:
    code = code or ""
    lang = normalize_language(language, filename)
    issues: list[Issue] = []
    python_ast_ok = True

    if lang == "python":
        python_issues, python_ast_ok = analyze_python(code, filename)
        issues.extend(python_issues)

    issues.extend(analyze_patterns(lang, code, python_ast_ok))

    engine = "static"
    if use_ai is None:
        use_ai = ai_enabled()
    if use_ai and ai_enabled():
        try:
            ai_issues = analyze_with_ai(code, filename, lang)
            issues = _merge(issues, ai_issues)
            engine = "static + AI"
        except Exception:
            engine = "static"

    issues = _sort(issues)
    score, metrics = _score(code, issues)
    return {
        "engine": engine,
        "score": score,
        "summary": _summary(metrics),
        "metrics": metrics,
        "issues": [asdict(issue) for issue in issues],
    }
