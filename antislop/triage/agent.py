"""
Autonomous Triage Agent: Synthesizes scan issues, groups root causes,
assesses architectural health, and generates prioritized executive insights.
"""

from typing import List, Dict
from antislop.models import TriageReport, TriageInsight, Issue, Severity, Category


class TriageAgent:
    """Intelligent triage reasoning agent that synthesizes code scan telemetry."""

    def triage(self, report: TriageReport) -> TriageReport:
        """Enriches the scan report with high-level triage insights and priority roadmaps."""
        insights: List[TriageInsight] = []
        issues = report.issues

        # 1. Evaluate Critical Credential & Secret Exposure
        secret_issues = [i for i in issues if i.category == Category.SECURITY and "SEC-00" in i.rule_id]
        if secret_issues:
            affected = sorted(list({i.file_path for i in secret_issues}))
            insights.append(TriageInsight(
                headline=f"Immediate Credential Exposure: {len(secret_issues)} Secret(s) Found in Plaintext",
                risk_level="CRITICAL",
                impact="Immediate credential theft, unauthorized API access, or data breaches if pushed to version control.",
                recommended_action="Revoke exposed credentials immediately and migrate to environment variables or secret vaults.",
                affected_files=affected
            ))

        # 2. Evaluate Dynamic Injection & Execution Risks
        injection_issues = [i for i in issues if i.rule_id in ("SEC-020", "SEC-021", "SEC-022", "SEC-023")]
        if injection_issues:
            affected = sorted(list({i.file_path for i in injection_issues}))
            insights.append(TriageInsight(
                headline=f"Dangerous Code/Command Injection Vectors ({len(injection_issues)} points)",
                risk_level="HIGH",
                impact="Potential remote code execution (RCE) or arbitrary database manipulation via unsanitized user inputs.",
                recommended_action="Refactor dynamic eval/exec and raw SQL string queries to use parameterized prepared statements.",
                affected_files=affected
            ))

        # 3. Evaluate Fault Tolerance & Silent Error Swallowing
        silent_catches = [i for i in issues if i.rule_id in ("GAP-001", "GAP-010")]
        if silent_catches:
            affected = sorted(list({i.file_path for i in silent_catches}))
            insights.append(TriageInsight(
                headline=f"Fault Tolerance Blindspots: {len(silent_catches)} Silent Error Catchers",
                risk_level="HIGH",
                impact="Runtime exceptions are silently discarded with 'pass' or empty handlers, making bug diagnosis impossible in production.",
                recommended_action="Introduce proper structured logging (e.g. logger.exception) and explicit error recovery mechanisms.",
                affected_files=affected
            ))

        # 4. Evaluate AI Slop & Codebase Hygiene
        slop_issues = [i for i in issues if i.category == Category.SLOP]
        if slop_issues:
            affected = sorted(list({i.file_path for i in slop_issues}))
            insights.append(TriageInsight(
                headline=f"AI Codebase Slop: {len(slop_issues)} Dead Imports, Chat Artifacts & Unfinished Placeholders",
                risk_level="MEDIUM",
                impact="Bloated codebase, increased bundle/image sizes, hallucinated dependencies, and developer confusion.",
                recommended_action="Run 'antislop fix' to prune dead imports, clean up AI conversational prompts, and address remaining TODO stubs.",
                affected_files=affected
            ))

        # 5. If clean codebase
        if not issues:
            insights.append(TriageInsight(
                headline="Clean Architecture: No Critical Security Flaws, AI Slop, or Gaps Detected",
                risk_level="INFO",
                impact="The repository conforms to high standards of hygiene, security, and error handling.",
                recommended_action="Maintain proactive CI/CD scanning with 'antislop scan --ci'.",
                affected_files=[]
            ))

        report.insights = insights
        return report

    @staticmethod
    def get_health_grade(score: float) -> str:
        if score >= 90:
            return "A+ (Excellent)"
        elif score >= 80:
            return "A (Good)"
        elif score >= 70:
            return "B (Moderate Risks)"
        elif score >= 50:
            return "C (Needs Attention)"
        elif score >= 30:
            return "D (High Risk)"
        else:
            return "F (Critical Vulnerabilities)"
