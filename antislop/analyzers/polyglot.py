"""
Polyglot and Infrastructure Analyzer: Inspects Dockerfiles, YAML/JSON configs,
Kubernetes manifests, and Shell scripts for architecture-agnostic risks.
"""

import re
from typing import List
from antislop.models import Issue, Severity, Category


class PolyglotAnalyzer:
    """Analyzes non-code assets (Docker, YAML, Shell, JSON) for security gaps and slop."""

    def analyze(self, file_path: str, content: str, language: str) -> List[Issue]:
        issues: List[Issue] = []
        lower_path = file_path.lower()

        if "dockerfile" in lower_path or language == "dockerfile":
            self._analyze_dockerfile(file_path, content, issues)
        elif language in ("yaml", "json") or lower_path.endswith((".yml", ".yaml", ".json")):
            self._analyze_configs(file_path, content, issues)
        elif language in ("shell", "powershell") or lower_path.endswith((".sh", ".bash", ".ps1")):
            self._analyze_shell(file_path, content, issues)

        return issues

    def _analyze_dockerfile(self, file_path: str, content: str, issues: List[Issue]):
        lines = content.splitlines()
        has_user_instruction = False

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # Check for unpinned latest tag
            from_match = re.search(r"""^FROM\s+([a-zA-Z0-9_\-\.\/]+)(?::([a-zA-Z0-9_\-\.]+))?""", stripped, re.IGNORECASE)
            if from_match:
                tag = from_match.group(2)
                if not tag or tag.lower() == "latest":
                    issues.append(Issue(
                        id=f"DOCKER-001-{idx}",
                        file_path=file_path,
                        line_number=idx,
                        rule_id="DOCKER-001",
                        title="Unpinned / Floating Docker Base Image Tag",
                        description=f"Using ':latest' or unpinned tag for base image '{from_match.group(1)}' makes builds non-reproducible.",
                        severity=Severity.LOW,
                        category=Category.GAPS,
                        code_snippet=stripped,
                        suggested_fix="Pin base image to an explicit version or digest (e.g. node:20-alpine or python:3.11-slim).",
                        confidence=0.90,
                        auto_fixable=False
                    ))

            # Check for apt-get install cache bloat
            if "apt-get install" in stripped and "rm -rf /var/lib/apt/lists" not in stripped:
                issues.append(Issue(
                    id=f"DOCKER-002-{idx}",
                    file_path=file_path,
                    line_number=idx,
                    rule_id="DOCKER-002",
                    title="Docker Image Bloat / Slop (Uncleaned apt cache)",
                    description="Package installation leaves package manager lists in image layers, inflating image size.",
                    severity=Severity.LOW,
                    category=Category.SLOP,
                    code_snippet=stripped[:100],
                    suggested_fix="Chain with '&& rm -rf /var/lib/apt/lists/*' in the same RUN layer.",
                    confidence=0.88,
                    auto_fixable=True
                ))

            if stripped.upper().startswith("USER "):
                has_user_instruction = True

        # Check if container runs as root
        if not has_user_instruction:
            issues.append(Issue(
                id="DOCKER-003-1",
                file_path=file_path,
                line_number=1,
                rule_id="DOCKER-003",
                title="Container Defaults to Root User Execution",
                description="No 'USER' instruction specified. Container will execute commands with full root privileges.",
                severity=Severity.MEDIUM,
                category=Category.SECURITY,
                code_snippet="Dockerfile lacks non-root USER instruction",
                suggested_fix="Add 'USER nonroot' or create a dedicated service account in the Dockerfile.",
                confidence=0.85,
                auto_fixable=False
            ))

    def _analyze_configs(self, file_path: str, content: str, issues: List[Issue]):
        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()

            # Privileged container in k8s / compose
            if re.search(r"""privileged\s*:\s*true""", stripped, re.IGNORECASE):
                issues.append(Issue(
                    id=f"CONF-001-{idx}",
                    file_path=file_path,
                    line_number=idx,
                    rule_id="CONF-001",
                    title="Excessive Privilege Granted in Configuration",
                    description="Container runs in privileged mode, disabling host isolation and container security profiles.",
                    severity=Severity.HIGH,
                    category=Category.SECURITY,
                    code_snippet=stripped,
                    suggested_fix="Remove 'privileged: true' and grant only specific Linux capabilities if required.",
                    confidence=0.95,
                    auto_fixable=True
                ))

            # Insecure plain HTTP endpoints in prod configs
            if re.search(r"""http:\/\/(?!(?:localhost|127\.0\.0\.1|0\.0\.0\.0))([a-zA-Z0-9_\-\.]+\.[a-zA-Z]{2,})""", stripped):
                issues.append(Issue(
                    id=f"CONF-002-{idx}",
                    file_path=file_path,
                    line_number=idx,
                    rule_id="CONF-002",
                    title="Insecure Plaintext HTTP URL in Configuration",
                    description="Plaintext HTTP protocol transmits unencrypted credentials and data over network.",
                    severity=Severity.MEDIUM,
                    category=Category.SECURITY,
                    code_snippet=stripped[:120],
                    suggested_fix="Enforce HTTPS URL schema for remote services.",
                    confidence=0.90,
                    auto_fixable=True
                ))

    def _analyze_shell(self, file_path: str, content: str, issues: List[Issue]):
        lines = content.splitlines()
        has_set_e = any(re.search(r"""set\s+-[a-zA-Z]*e""", line) for line in lines)

        if not has_set_e and len(lines) > 5:
            issues.append(Issue(
                id="SH-001-1",
                file_path=file_path,
                line_number=1,
                rule_id="SH-001",
                title="Missing Strict Error Trap in Shell Script (set -e)",
                description="Shell script continues execution even if intermediate commands fail, leading to silent pipeline errors.",
                severity=Severity.MEDIUM,
                category=Category.GAPS,
                code_snippet=lines[0] if lines else "",
                suggested_fix="Add 'set -euo pipefail' near the top of the shell script.",
                confidence=0.90,
                auto_fixable=True
            ))
