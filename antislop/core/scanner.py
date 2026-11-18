"""
Filesystem scanner & dispatcher: Discovers files, applies ignore rules,
determines language context, and dispatches to analyzers.
"""

import os
import time
from datetime import datetime
from pathlib import Path
from typing import List

from antislop.config import ScanConfig, SUPPORTED_EXTENSIONS
from antislop.models import Issue, ScanSummary, TriageReport
from antislop.analyzers.security import SecurityAnalyzer
from antislop.analyzers.slop import SlopAnalyzer
from antislop.analyzers.gaps import GapAnalyzer
from antislop.analyzers.polyglot import PolyglotAnalyzer


class RepositoryScanner:
    """Scans repositories in an architecture-agnostic manner."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.security_analyzer = SecurityAnalyzer(entropy_threshold=config.entropy_threshold)
        self.slop_analyzer = SlopAnalyzer()
        self.gap_analyzer = GapAnalyzer()
        self.polyglot_analyzer = PolyglotAnalyzer()

    def scan(self) -> TriageReport:
        start_time = time.time()
        root_path = Path(self.config.target_path).resolve()

        all_issues: List[Issue] = []
        files_scanned = 0
        lines_scanned = 0

        # Scan targets
        if root_path.is_file():
            files_to_scan = [root_path]
        else:
            files_to_scan = self._discover_files(root_path)

        for file_path in files_to_scan:
            try:
                rel_path = str(file_path.relative_to(root_path)) if file_path != root_path else file_path.name
            except ValueError:
                rel_path = str(file_path)

            file_size_kb = file_path.stat().st_size / 1024.0
            if file_size_kb > self.config.max_file_size_kb:
                continue

            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            language = self._detect_language(file_path)
            if not language:
                continue

            files_scanned += 1
            file_lines = len(content.splitlines())
            lines_scanned += file_lines

            # Dispatch analyzers based on configuration
            if self.config.enable_security:
                all_issues.extend(self.security_analyzer.analyze(rel_path, content, language))

            if self.config.enable_slop:
                all_issues.extend(self.slop_analyzer.analyze(rel_path, content, language))

            if self.config.enable_gaps:
                all_issues.extend(self.gap_analyzer.analyze(rel_path, content, language))

            all_issues.extend(self.polyglot_analyzer.analyze(rel_path, content, language))

        duration = time.time() - start_time

        # Compile Summary
        summary = ScanSummary(
            files_scanned=files_scanned,
            lines_scanned=lines_scanned,
            duration_seconds=round(duration, 3)
        )

        for issue in all_issues:
            sev_val = issue.severity.value
            cat_val = issue.category.value
            if sev_val in summary.issues_by_severity:
                summary.issues_by_severity[sev_val] += 1
            if cat_val in summary.issues_by_category:
                summary.issues_by_category[cat_val] += 1

        summary.compute_health_score(len(all_issues))

        auto_fix_count = sum(1 for iss in all_issues if iss.auto_fixable)

        return TriageReport(
            project_root=str(root_path),
            timestamp=datetime.now().isoformat(),
            summary=summary,
            issues=all_issues,
            insights=[],
            remediations_available=auto_fix_count
        )

    def _discover_files(self, root: Path) -> List[Path]:
        discovered: List[Path] = []
        for dirpath, dirnames, filenames in os.walk(root):
            # Prune ignored directories in-place
            dirnames[:] = [d for d in dirnames if not self._is_dir_ignored(d, dirpath)]

            for fname in filenames:
                file_full = Path(dirpath) / fname
                rel = str(file_full.relative_to(root))
                if not self.config.is_file_ignored(rel):
                    discovered.append(file_full)
        return discovered

    def _is_dir_ignored(self, dirname: str, parent: str) -> bool:
        if dirname in self.config.ignore_dirs:
            return True
        if dirname.startswith("."):
            return True
        return False

    def _detect_language(self, path: Path) -> str:
        name_lower = path.name.lower()
        if "dockerfile" in name_lower:
            return "dockerfile"
        if name_lower in ("gemfile", "rakefile"):
            return "ruby"

        suffix = path.suffix.lower()
        if suffix in SUPPORTED_EXTENSIONS:
            return SUPPORTED_EXTENSIONS[suffix]

        # Check shebang line if no known extension
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                first_line = f.readline()
                if first_line.startswith("#!"):
                    first_lower = first_line.lower()
                    if "python" in first_lower:
                        return "python"
                    if "node" in first_lower or "js" in first_lower:
                        return "javascript"
                    if "php" in first_lower:
                        return "php"
                    if "ruby" in first_lower:
                        return "ruby"
                    if "sh" in first_lower or "bash" in first_lower:
                        return "shell"
        except Exception:
            pass

        return "generic"
