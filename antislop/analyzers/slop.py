"""
AI Slop Analyzer: Detects phantom imports, boilerplate debris, dead functions,
AI chat artifacts, placeholder leftovers, and tautological wrappers.
"""

import ast
import re
from typing import List, Set
from antislop.models import Issue, Severity, Category

# Signatures of LLM chat responses accidentally pasted into codebases
LLM_CHAT_ARTIFACTS = [
    re.compile(r"""(?i)^\s*(?:#|\/\/|\/\*)\s*(?:Certainly!|Here is the (?:code|implementation)|As an AI language model|Hope this helps|Note: make sure to replace|Let me know if you need)"""),
    re.compile(r"""(?i)^\s*(?:#|\/\/)\s*```(?:python|javascript|typescript|bash|json)?"""),
    re.compile(r"""(?i)<(?:insert|your)[_\s-]+(?:key|code|logic|path|token|endpoint)[_\s-]*>"""),
    re.compile(r"""(?i)['\"](?:YOUR[_\s-]API[_\s-]KEY|INSERT[_\s-]YOUR[_\s-]TOKEN)['\"]"""),
]

# Common placeholder docstrings and comments left by AI assistants
PLACEHOLDER_PATTERNS = [
    ("SLOP-002", "Unaddressed AI Placeholder / TODO Marker", Severity.MEDIUM,
     re.compile(r"""(?i)(?:#|\/\/)\s*(?:TODO|FIXME|HACK|XXX)\s*:\s*(?:implement|add logic|handle error|finish this|fill this in|temporary fix)"""),
     "Implement the required logic or remove the incomplete placeholder."),

    ("SLOP-003", "Placeholder / Mock Value Left in Production Code", Severity.LOW,
     re.compile(r"""(?i)(?:['\"]lorem ipsum['\"]|test_foo_bar_dummy|dummy_mock_data_123)"""),
     "Replace dummy placeholder data with genuine production data fixtures."),
]


class SlopAnalyzer:
    """Analyzes source files for AI slop, dead code, and hallucinated wrappers."""

    def analyze(self, file_path: str, content: str, language: str) -> List[Issue]:
        issues: List[Issue] = []
        lines = content.splitlines()

        # Check line-by-line artifacts
        for line_idx, line in enumerate(lines, start=1):
            # Check LLM Chat Artifacts (e.g. "Certainly! Here is...")
            for pat in LLM_CHAT_ARTIFACTS:
                if pat.search(line):
                    issues.append(Issue(
                        id=f"SLOP-001-{line_idx}",
                        file_path=file_path,
                        line_number=line_idx,
                        rule_id="SLOP-001",
                        title="AI Assistant Chat Artifact Pasted in Code",
                        description="Found chat preamble or conversational text accidentally pasted from an AI assistant.",
                        severity=Severity.HIGH,
                        category=Category.SLOP,
                        code_snippet=line.strip()[:120],
                        suggested_fix="Delete conversational AI artifacts and Markdown code fence markers.",
                        confidence=0.98,
                        auto_fixable=True,
                        metadata={"rule_type": "ai_artifact"}
                    ))
                    break

            # Check Placeholder / TODO leftovers
            for rule_id, title, severity, pat, fix in PLACEHOLDER_PATTERNS:
                if pat.search(line):
                    issues.append(Issue(
                        id=f"{rule_id}-{line_idx}",
                        file_path=file_path,
                        line_number=line_idx,
                        rule_id=rule_id,
                        title=title,
                        description=f"Unresolved AI task/stub: '{line.strip()[:80]}'",
                        severity=severity,
                        category=Category.SLOP,
                        code_snippet=line.strip()[:120],
                        suggested_fix=fix,
                        confidence=0.92,
                        auto_fixable=False,
                    ))

        # Language-specific import & slop analysis
        if language == "python":
            self._analyze_python_ast(file_path, content, issues)
        elif language in ("javascript", "typescript"):
            self._analyze_js_slop(file_path, content, issues)
        elif language == "go":
            self._analyze_go_slop(file_path, content, issues)
        elif language == "php":
            self._analyze_php_slop(file_path, content, issues)
        elif language == "ruby":
            self._analyze_ruby_slop(file_path, content, issues)

        return issues

    def _analyze_python_ast(self, file_path: str, content: str, issues: List[Issue]):
        """Parses Python AST to locate unused imports, dead functions, and tautologies."""
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return

        # Do not flag unused imports in __init__.py or test files (re-exports / discovery)
        is_reexport_file = file_path.endswith("__init__.py") or "test" in file_path.lower()

        # 1. Detect Unused Imports without false positives
        if not is_reexport_file:
            imported_symbols: dict[str, tuple[str, int]] = {}
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        name = alias.asname or alias.name
                        imported_symbols[name] = (alias.name, node.lineno)
                elif isinstance(node, ast.ImportFrom):
                    for alias in node.names:
                        name = alias.asname or alias.name
                        imported_symbols[name] = (alias.name, node.lineno)

            # Check explicit __all__ exports
            all_exports = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name) and target.id == "__all__":
                            if isinstance(node.value, (ast.List, ast.Tuple, ast.Set)):
                                for elt in node.value.elts:
                                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                        all_exports.add(elt.value)

            for sym, (orig_name, lineno) in imported_symbols.items():
                if sym.startswith("__") or sym in all_exports:
                    continue
                # Verify total occurrences across the entire file content
                # If it appears more than once, it is used in docstrings, annotations, or expressions
                occurrences = len(re.findall(rf"\b{re.escape(sym)}\b", content))
                if occurrences <= 1:
                    issues.append(Issue(
                        id=f"SLOP-010-{lineno}",
                        file_path=file_path,
                        line_number=lineno,
                        rule_id="SLOP-010",
                        title=f"Unused / Ghost Import '{sym}'",
                        description=f"Import '{orig_name}' is loaded but never utilized in this module. Common in AI-generated files.",
                        severity=Severity.LOW,
                        category=Category.SLOP,
                        code_snippet=f"import/from ... {sym}",
                        suggested_fix=f"Remove the unused import '{sym}'.",
                        confidence=0.95,
                        auto_fixable=True,
                        metadata={"symbol": sym, "line": lineno}
                    ))

        # 2. Detect Empty / Stubbed Functions (Boilerplate Slop)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # If body is only a docstring, pass, or ellipsis
                real_statements = [
                    stmt for stmt in node.body
                    if not (isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str))
                ]
                if len(real_statements) == 1:
                    stmt = real_statements[0]
                    if isinstance(stmt, ast.Pass) or (isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and stmt.value.value is Ellipsis):
                        issues.append(Issue(
                            id=f"SLOP-011-{node.lineno}",
                            file_path=file_path,
                            line_number=node.lineno,
                            rule_id="SLOP-011",
                            title=f"Empty Stub / Hollow Function '{node.name}'",
                            description=f"Function '{node.name}' contains no logic beyond pass/ellipsis. Often generated by LLMs as unfinished boilerplate.",
                            severity=Severity.MEDIUM,
                            category=Category.SLOP,
                            code_snippet=f"def {node.name}(...): pass",
                            suggested_fix=f"Implement business logic for '{node.name}' or remove the dead declaration.",
                            confidence=0.90,
                            auto_fixable=False,
                        ))

                # 3. Detect Tautological / Redundant 1-to-1 Wrappers
                # e.g.: def helper(x): return x
                if len(real_statements) == 1 and isinstance(real_statements[0], ast.Return):
                    ret_node = real_statements[0]
                    if isinstance(ret_node.value, ast.Name) and len(node.args.args) == 1:
                        if ret_node.value.id == node.args.args[0].arg and not node.name.startswith("__"):
                            issues.append(Issue(
                                id=f"SLOP-012-{node.lineno}",
                                file_path=file_path,
                                line_number=node.lineno,
                                rule_id="SLOP-012",
                                title=f"Tautological Identity Wrapper '{node.name}'",
                                description=f"Function '{node.name}' simply returns its single argument untouched with no processing.",
                                severity=Severity.LOW,
                                category=Category.SLOP,
                                code_snippet=f"def {node.name}({node.args.args[0].arg}): return {node.args.args[0].arg}",
                                suggested_fix="Remove unnecessary identity wrapper.",
                                confidence=0.88,
                                auto_fixable=False
                            ))

    def _analyze_js_slop(self, file_path: str, content: str, issues: List[Issue]):
        """Heuristic analysis for JavaScript/TypeScript slop and ghost imports."""
        lines = content.splitlines()
        import_pat = re.compile(r"""(?:import\s+(?:{([^}]+)}|([a-zA-Z0-9_$]+))\s+from|const\s+([a-zA-Z0-9_$]+)\s*=\s*require\()""")

        for line_idx, line in enumerate(lines, start=1):
            match = import_pat.search(line)
            if match:
                named = match.group(1)
                default_name = match.group(2) or match.group(3)
                symbols_to_check = []
                if named:
                    symbols_to_check.extend([s.strip().split(" as ")[-1] for s in named.split(",") if s.strip()])
                elif default_name:
                    symbols_to_check.append(default_name.strip())

                for sym in symbols_to_check:
                    # Count occurrences in entire file
                    occurrences = len(re.findall(rf"\b{re.escape(sym)}\b", content))
                    if occurrences <= 1:
                        issues.append(Issue(
                            id=f"SLOP-020-{line_idx}",
                            file_path=file_path,
                            line_number=line_idx,
                            rule_id="SLOP-020",
                            title=f"Unused JS/TS Import '{sym}'",
                            description=f"Import '{sym}' is declared on line {line_idx} but never referenced anywhere in this module.",
                            severity=Severity.LOW,
                            category=Category.SLOP,
                            code_snippet=line.strip()[:100],
                            suggested_fix=f"Remove '{sym}' from the import statement.",
                            confidence=0.92,
                            auto_fixable=True,
                            metadata={"symbol": sym}
                        ))

    def _analyze_go_slop(self, file_path: str, content: str, issues: List[Issue]):
        """Detects unused imports and stubs in Go files."""
        # Find all Go package imports
        import_blocks = re.findall(r"""import\s*\((.*?)\)""", content, re.DOTALL)
        single_imports = re.findall(r"""import\s+["']([^"']+)["']""", content)
        pkgs = list(single_imports)
        for block in import_blocks:
            pkgs.extend(re.findall(r"""["']([^"']+)["']""", block))

        for pkg in pkgs:
            pkg_name = pkg.split("/")[-1]
            if pkg_name in ("C", "_", ""):
                continue
            if len(re.findall(rf"\b{re.escape(pkg_name)}\b", content)) <= 1:
                issues.append(Issue(
                    id="SLOP-030-1",
                    file_path=file_path,
                    line_number=1,
                    rule_id="SLOP-030",
                    title=f"Unused Go Package Import '{pkg}'",
                    description=f"Package '{pkg}' is imported but not referenced.",
                    severity=Severity.LOW,
                    category=Category.SLOP,
                    code_snippet=f'import "{pkg}"',
                    suggested_fix=f"Remove unused import '{pkg}'.",
                    confidence=0.92,
                    auto_fixable=True
                ))

    def _analyze_php_slop(self, file_path: str, content: str, issues: List[Issue]):
        """Detects unused use declarations and stubs in PHP files."""
        use_matches = re.finditer(r"""(?i)^\s*use\s+([\\a-zA-Z0-9_]+(?:\s+as\s+([a-zA-Z0-9_]+))?)\s*;""", content, re.MULTILINE)
        for match in use_matches:
            full = match.group(1)
            alias = match.group(2)
            sym = alias if alias else full.split("\\")[-1]
            if len(re.findall(rf"\b{re.escape(sym)}\b", content)) <= 1:
                line_no = content[:match.start()].count("\n") + 1
                issues.append(Issue(
                    id=f"SLOP-040-{line_no}",
                    file_path=file_path,
                    line_number=line_no,
                    rule_id="SLOP-040",
                    title=f"Unused PHP Class Import 'use {sym}'",
                    description=f"PHP use declaration '{full}' is never referenced in this script.",
                    severity=Severity.LOW,
                    category=Category.SLOP,
                    code_snippet=f"use {full};",
                    suggested_fix=f"Remove unused 'use {full};' statement.",
                    confidence=0.92,
                    auto_fixable=True
                ))

    def _analyze_ruby_slop(self, file_path: str, content: str, issues: List[Issue]):
        """Detects unused requires in Ruby files."""
        req_matches = re.finditer(r"""^\s*require(?:_relative)?\s+['"]([^'"]+)['"]""", content, re.MULTILINE)
        for match in req_matches:
            pkg = match.group(1).split("/")[-1].replace(".rb", "")
            const_name = "".join(w.capitalize() for w in pkg.split("_"))
            if len(re.findall(rf"\b(?:{re.escape(pkg)}|{re.escape(const_name)})\b", content)) <= 1:
                line_no = content[:match.start()].count("\n") + 1
                issues.append(Issue(
                    id=f"SLOP-050-{line_no}",
                    file_path=file_path,
                    line_number=line_no,
                    rule_id="SLOP-050",
                    title=f"Unused Ruby Dependency 'require \"{pkg}\"'",
                    description=f"Ruby requirement '{pkg}' is never referenced.",
                    severity=Severity.LOW,
                    category=Category.SLOP,
                    code_snippet=f"require '{pkg}'",
                    suggested_fix=f"Remove unused 'require \"{pkg}\"'.",
                    confidence=0.90,
                    auto_fixable=True
                ))
