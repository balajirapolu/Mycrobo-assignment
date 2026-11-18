"""
Coding Gaps & Loose Ends Analyzer: Detects silent exception swallowers,
unclosed resource leaks, unreachable code, unimplemented stubs, and missing fallbacks.
"""

import ast
import re
from typing import List
from antislop.models import Issue, Severity, Category

# Polyglot patterns for silent exception suppression
POLYGLOT_GAP_PATTERNS = [
    ("GAP-001", "Silent Exception Swallowing in JS/TS/Java", Severity.HIGH,
     re.compile(r"""catch\s*\([^\)]*\)\s*\{\s*(?:\/\/[^\n]*|\/\*.*?\*\/)?\s*\}"""),
     "Log the caught exception or rethrow: console.error(err) or throw err."),

    ("GAP-002", "Unimplemented Stub Error (throw Not Implemented)", Severity.MEDIUM,
     re.compile(r"""throw\s+new\s+Error\s*\(\s*['\"](?:Not implemented|TODO|stub)['\"]"""),
     "Implement the required business logic before shipping to production."),

    ("GAP-003", "Missing Async Promise Rejection Handler", Severity.MEDIUM,
     re.compile(r"""\.\s*then\s*\([^\)]+\)(?!\s*\.\s*catch)"""),
     "Chain a .catch(err => ...) handler to avoid unhandled promise rejections."),

    ("GAP-004", "Hardcoded Magic Return Value (-1 or null fallback)", Severity.LOW,
     re.compile(r"""return\s+(?:-999|-1|null|undefined)\s*;\s*\/\/\s*fallback"""),
     "Use explicit Optional / Result types or raise domain-specific errors."),
]


class GapAnalyzer:
    """Analyzes source code for critical coding gaps, loose ends, and unhandled errors."""

    def analyze(self, file_path: str, content: str, language: str) -> List[Issue]:
        issues: List[Issue] = []

        # Polyglot regex checks
        lines = content.splitlines()
        for line_idx, line in enumerate(lines, start=1):
            for rule_id, title, severity, pat, fix in POLYGLOT_GAP_PATTERNS:
                match = pat.search(line)
                if match:
                    issues.append(Issue(
                        id=f"{rule_id}-{line_idx}",
                        file_path=file_path,
                        line_number=line_idx,
                        rule_id=rule_id,
                        title=title,
                        description=f"Coding gap detected: {match.group(0)[:60]}",
                        severity=severity,
                        category=Category.GAPS,
                        code_snippet=line.strip()[:120],
                        suggested_fix=fix,
                        confidence=0.92,
                        auto_fixable=False,
                    ))

        # Deep Python AST analysis for gaps
        if language == "python":
            self._analyze_python_gaps(file_path, content, issues)

        return issues

    def _analyze_python_gaps(self, file_path: str, content: str, issues: List[Issue]):
        """Detects Python-specific gaps: silent except pass, unclosed file handles, unreachable code."""
        try:
            tree = ast.parse(content)
        except SyntaxError as e:
            issues.append(Issue(
                id=f"GAP-SYNTAX-{e.lineno or 1}",
                file_path=file_path,
                line_number=e.lineno or 1,
                rule_id="GAP-099",
                title="Fatal Syntax Error / Broken Parser Gap",
                description=f"File fails to parse: {e.msg}",
                severity=Severity.CRITICAL,
                category=Category.GAPS,
                code_snippet=str(e.text).strip() if e.text else "",
                suggested_fix="Fix code syntax to allow execution and static analysis.",
                confidence=1.0,
                auto_fixable=False
            ))
            return

        for node in ast.walk(tree):
            # 1. Detect Silent 'except: pass' or 'except Exception: pass'
            if isinstance(node, ast.ExceptHandler):
                is_silent = False
                if len(node.body) == 1:
                    stmt = node.body[0]
                    if isinstance(stmt, ast.Pass):
                        is_silent = True
                    elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and stmt.value.value is Ellipsis:
                        is_silent = True

                if is_silent:
                    name_type = "bare except" if node.type is None else ast.unparse(node.type)
                    issues.append(Issue(
                        id=f"GAP-010-{node.lineno}",
                        file_path=file_path,
                        line_number=node.lineno,
                        rule_id="GAP-010",
                        title=f"Silent Exception Swallowing ('except {name_type}: pass')",
                        description="Exceptions are silently ignored with pass. Errors and failures will be masked.",
                        severity=Severity.HIGH,
                        category=Category.GAPS,
                        code_snippet=f"except {name_type}: pass",
                        suggested_fix="Log the exception with logging.exception() or handle the specific failure case.",
                        confidence=0.98,
                        auto_fixable=True,
                        metadata={"rule_type": "swallowed_exception"}
                    ))

            # 2. Detect Resource Leak: open() not in 'with' statement
            if isinstance(node, ast.Assign):
                if isinstance(node.value, ast.Call):
                    func = node.value.func
                    if isinstance(func, ast.Name) and func.id == "open":
                        # Check if this assignment is inside a with block
                        issues.append(Issue(
                            id=f"GAP-020-{node.lineno}",
                            file_path=file_path,
                            line_number=node.lineno,
                            rule_id="GAP-020",
                            title="Unmanaged File Descriptor (Missing 'with open(...)')",
                            description="File opened directly via assignment without context manager. May cause file descriptor leaks.",
                            severity=Severity.MEDIUM,
                            category=Category.GAPS,
                            code_snippet=ast.unparse(node)[:100],
                            suggested_fix="Use context manager: 'with open(...) as f:' to guarantee file closure.",
                            confidence=0.89,
                            auto_fixable=True
                        ))

            # 3. Detect Unimplemented Stubs: raise NotImplementedError
            if isinstance(node, ast.Raise):
                if node.exc:
                    exc_name = ""
                    if isinstance(node.exc, ast.Call) and isinstance(node.exc.func, ast.Name):
                        exc_name = node.exc.func.id
                    elif isinstance(node.exc, ast.Name):
                        exc_name = node.exc.id

                    if exc_name == "NotImplementedError":
                        issues.append(Issue(
                            id=f"GAP-030-{node.lineno}",
                            file_path=file_path,
                            line_number=node.lineno,
                            rule_id="GAP-030",
                            title="Unimplemented Code Stub (raise NotImplementedError)",
                            description="Production code execution will crash at runtime due to incomplete stub.",
                            severity=Severity.HIGH,
                            category=Category.GAPS,
                            code_snippet="raise NotImplementedError(...)",
                            suggested_fix="Complete implementation or supply default fallback behavior.",
                            confidence=0.95,
                            auto_fixable=False
                        ))

            # 4. Detect Unreachable Code after Return / Raise
            if hasattr(node, "body") and isinstance(node.body, list):
                has_terminal = False
                terminal_line = 0
                for stmt in node.body:
                    if has_terminal:
                        issues.append(Issue(
                            id=f"GAP-040-{stmt.lineno}",
                            file_path=file_path,
                            line_number=stmt.lineno,
                            rule_id="GAP-040",
                            title="Unreachable Dead Code",
                            description=f"Statement is unreachable; previous line ({terminal_line}) unconditionally terminated execution.",
                            severity=Severity.LOW,
                            category=Category.GAPS,
                            code_snippet=ast.unparse(stmt)[:80] if hasattr(ast, "unparse") else "",
                            suggested_fix="Delete unreachable dead code or correct branch control flow.",
                            confidence=0.92,
                            auto_fixable=True
                        ))
                        break
                    if isinstance(stmt, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
                        has_terminal = True
                        terminal_line = stmt.lineno
