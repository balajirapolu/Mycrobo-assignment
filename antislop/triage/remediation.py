"""
Auto-Remediation Engine: Generates diffs, patches, and automated fixes
for detected AI slop, leaked secrets, and silent error swallowers.
"""

import difflib
import re
from pathlib import Path
from typing import Dict, List, Tuple
from antislop.models import Issue, TriageReport, Category


class RemediationEngine:
    """Applies automated code refactoring and generates patches for fixable issues."""

    def generate_patches(self, report: TriageReport) -> Dict[str, Tuple[str, str, str]]:
        """
        Returns a dict: file_path -> (original_content, patched_content, unified_diff)
        """
        patches: Dict[str, Tuple[str, str, str]] = {}
        issues_by_file: Dict[str, List[Issue]] = {}

        for iss in report.issues:
            if iss.auto_fixable:
                issues_by_file.setdefault(iss.file_path, []).append(iss)

        root = Path(report.project_root)

        for rel_path, file_issues in issues_by_file.items():
            full_path = root / rel_path
            if not full_path.exists() or not full_path.is_file():
                continue

            try:
                original_content = full_path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            patched_content = self._apply_fixes_to_content(original_content, file_issues)
            if patched_content != original_content:
                orig_lines = original_content.splitlines(keepends=True)
                patch_lines = patched_content.splitlines(keepends=True)
                diff = "".join(difflib.unified_diff(
                    orig_lines, patch_lines,
                    fromfile=f"a/{rel_path}",
                    tofile=f"b/{rel_path}"
                ))
                patches[rel_path] = (original_content, patched_content, diff)

        return patches

    def apply_patches(self, patches: Dict[str, Tuple[str, str, str]], project_root: str) -> int:
        """Writes patched contents to disk. Returns count of files updated."""
        root = Path(project_root)
        applied_count = 0
        for rel_path, (_, patched, _) in patches.items():
            full_path = root / rel_path
            try:
                full_path.write_text(patched, encoding="utf-8")
                applied_count += 1
            except Exception:
                pass
        return applied_count

    def _apply_fixes_to_content(self, content: str, issues: List[Issue]) -> str:
        lines = content.splitlines()

        # Sort issues by line number in descending order to avoid line shift issues
        sorted_issues = sorted(issues, key=lambda i: i.line_number, reverse=True)

        for iss in sorted_issues:
            idx = iss.line_number - 1
            if idx < 0 or idx >= len(lines):
                continue

            current_line = lines[idx]

            # 1. Fix AI conversational artifacts: delete line
            if iss.rule_id == "SLOP-001":
                lines.pop(idx)
                continue

            # 2. Fix Unused Imports in Python / JS
            if iss.rule_id in ("SLOP-010", "SLOP-020"):
                sym = iss.metadata.get("symbol", "")
                if sym:
                    # If whole import line is only that symbol, remove or comment it
                    if re.search(rf"""^\s*(?:import\s+{re.escape(sym)}|from\s+[\w\.]+\s+import\s+{re.escape(sym)})\s*$""", current_line):
                        lines.pop(idx)
                        continue
                    else:
                        # Multi-import: remove just the symbol from comma list
                        modified = re.sub(rf"""\b{re.escape(sym)}\b\s*,?\s*""", "", current_line)
                        lines[idx] = modified.rstrip(", ")

            # 3. Fix Silent Exception Swallowing
            if iss.rule_id == "GAP-010":
                indent = len(current_line) - len(current_line.lstrip())
                indent_str = " " * (indent + 4)
                # Check next line
                if idx + 1 < len(lines):
                    next_line = lines[idx + 1]
                    if next_line.strip() == "pass":
                        lines[idx + 1] = f"{indent_str}import logging; logging.warning('Exception caught in fallback')"

            # 4. Fix Leaked secrets: mask or replace with os.getenv
            if "SEC-00" in iss.rule_id:
                # Replace the raw key with os.getenv
                replaced = re.sub(
                    r"""(['\"])(?:sk-[a-zA-Z0-9_\-]{20,}|ghp_[a-zA-Z0-9]{36}|AKIA[0-9A-Z]{16})(['\"])""",
                    r"""os.getenv("SECRET_KEY", "SET_IN_ENVIRONMENT")""",
                    current_line
                )
                lines[idx] = replaced

            # 5. Fix Docker apt list cleanup
            if iss.rule_id == "DOCKER-002":
                if "&& rm -rf /var/lib/apt/lists" not in current_line:
                    lines[idx] = current_line + " && rm -rf /var/lib/apt/lists/*"

        return "\n".join(lines) + ("\n" if content.endswith("\n") else "")
