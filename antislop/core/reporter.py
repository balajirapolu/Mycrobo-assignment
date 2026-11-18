"""
Reporting engines: Rich console formatting, SARIF v2.1.0 (GitHub standard), JSON, and standalone HTML Dashboard.
"""

import json
import html
from typing import Dict, Any
from antislop.models import TriageReport, Severity, Category
from antislop.triage.agent import TriageAgent

# ANSI Color Codes for terminal
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
WHITE = "\033[37m"
GRAY = "\033[90m"


class ConsoleReporter:
    """Formats and prints an interactive triage report to standard output."""

    @staticmethod
    def render(report: TriageReport) -> str:
        out = []
        summary = report.summary
        grade = TriageAgent.get_health_grade(summary.health_score)

        # Header Banner
        out.append(f"\n{BOLD}{CYAN}================================================================================{RESET}")
        out.append(f"{BOLD}{CYAN}   SLOPSENTINEL: Architecture-Agnostic Anti-Slop & Security Triage Agent        {RESET}")
        out.append(f"{BOLD}{CYAN}================================================================================{RESET}\n")

        # Health Score Card
        score_color = GREEN if summary.health_score >= 80 else (YELLOW if summary.health_score >= 50 else RED)
        out.append(f"  {BOLD}Target:{RESET} {report.project_root}")
        out.append(f"  {BOLD}Files Scanned:{RESET} {summary.files_scanned} | {BOLD}Lines:{RESET} {summary.lines_scanned:,} | {BOLD}Scan Time:{RESET} {summary.duration_seconds}s")
        out.append(f"  {BOLD}Codebase Health Score:{RESET} {score_color}{summary.health_score}/100 [{grade}]{RESET}\n")

        # Category & Severity Matrix
        out.append(f"{BOLD}--- TRIAGE SUMMARY MATRIX ------------------------------------------------------{RESET}")
        sev_counts = summary.issues_by_severity
        cat_counts = summary.issues_by_category

        out.append(
            f"  {RED}{BOLD}Critical:{RESET} {sev_counts.get('CRITICAL', 0):<3} | "
            f"{YELLOW}{BOLD}High:{RESET} {sev_counts.get('HIGH', 0):<3} | "
            f"{CYAN}Medium:{RESET} {sev_counts.get('MEDIUM', 0):<3} | "
            f"{GRAY}Low/Info:{RESET} {sev_counts.get('LOW', 0) + sev_counts.get('INFO', 0):<3}"
        )
        out.append(
            f"  {RED}🛡️  Security:{RESET} {cat_counts.get('SECURITY', 0):<3} | "
            f"{YELLOW}🧹 AI Slop:{RESET} {cat_counts.get('SLOP', 0):<3} | "
            f"{BLUE}🔍 Coding Gaps:{RESET} {cat_counts.get('GAPS', 0):<3} | "
            f"{GREEN}⚡ Auto-Fixable:{RESET} {report.remediations_available:<3}\n"
        )

        # Executive Insights
        if report.insights:
            out.append(f"{BOLD}--- EXECUTIVE TRIAGE INSIGHTS --------------------------------------------------{RESET}")
            for insight in report.insights:
                color = RED if insight.risk_level == "CRITICAL" else (YELLOW if insight.risk_level == "HIGH" else CYAN)
                out.append(f"  [{color}{BOLD}{insight.risk_level}{RESET}] {BOLD}{insight.headline}{RESET}")
                out.append(f"    {GRAY}Impact:{RESET} {insight.impact}")
                out.append(f"    {GREEN}Action:{RESET} {insight.recommended_action}")
                if insight.affected_files:
                    sample_files = ", ".join(insight.affected_files[:3])
                    if len(insight.affected_files) > 3:
                        sample_files += f" (+{len(insight.affected_files)-3} more)"
                    out.append(f"    {GRAY}Affected:{RESET} {sample_files}")
                out.append("")

        # Issues Breakdown
        if report.issues:
            out.append(f"{BOLD}--- DETECTED ISSUES & ACTIONS ({len(report.issues)} total) -----------------------------------{RESET}")
            for idx, iss in enumerate(report.issues[:25], start=1):
                sev_color = RED if iss.severity == Severity.CRITICAL else (YELLOW if iss.severity == Severity.HIGH else CYAN)
                fix_tag = f"{GREEN}[AUTO-FIXABLE]{RESET} " if iss.auto_fixable else ""
                out.append(f"  {BOLD}#{idx}{RESET} [{sev_color}{iss.severity.value}{RESET}] [{iss.category.value}] {BOLD}{iss.title}{RESET} ({iss.rule_id})")
                out.append(f"     Location: {iss.file_path}:{iss.line_number}")
                if iss.code_snippet:
                    out.append(f"     Snippet:  {GRAY}{iss.code_snippet}{RESET}")
                out.append(f"     Fix:      {fix_tag}{iss.suggested_fix}\n")

            if len(report.issues) > 25:
                out.append(f"  {GRAY}... and {len(report.issues) - 25} more issues. (Use --format html or json for full report){RESET}\n")

        out.append(f"{CYAN}================================================================================{RESET}")
        return "\n".join(out)


class SarifReporter:
    """Formats report as SARIF v2.1.0 for GitHub Security tab & CI/CD workflows."""

    @staticmethod
    def render(report: TriageReport) -> str:
        rules_map = {}
        results = []

        for issue in report.issues:
            if issue.rule_id not in rules_map:
                rules_map[issue.rule_id] = {
                    "id": issue.rule_id,
                    "name": issue.title,
                    "shortDescription": {"text": issue.title},
                    "fullDescription": {"text": issue.description},
                    "defaultConfiguration": {
                        "level": "error" if issue.severity in (Severity.CRITICAL, Severity.HIGH) else "warning"
                    }
                }

            results.append({
                "ruleId": issue.rule_id,
                "level": "error" if issue.severity in (Severity.CRITICAL, Severity.HIGH) else "warning",
                "message": {"text": f"{issue.title}: {issue.description}. Fix: {issue.suggested_fix}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": issue.file_path.replace("\\", "/")},
                        "region": {"startLine": max(1, issue.line_number)}
                    }
                }]
            })

        sarif_doc = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "SlopSentinel",
                        "semanticVersion": "1.0.0",
                        "informationUri": "https://github.com/balajirapolu/anti-slop-agent",
                        "rules": list(rules_map.values())
                    }
                },
                "results": results
            }]
        }
        return json.dumps(sarif_doc, indent=2)


class HtmlReporter:
    """Generates a standalone, dark-themed responsive HTML dashboard."""

    @staticmethod
    def render(report: TriageReport) -> str:
        s = report.summary
        grade = TriageAgent.get_health_grade(s.health_score)

        # Build issue cards
        issue_cards = []
        for i, iss in enumerate(report.issues, 1):
            sev_class = iss.severity.value.lower()
            cat_badge = iss.category.value
            snippet_html = f"<pre><code>{html.escape(iss.code_snippet)}</code></pre>" if iss.code_snippet else ""
            fixable_badge = '<span class="badge fixable">⚡ Auto-Fixable</span>' if iss.auto_fixable else ""

            issue_cards.append(f"""
            <div class="issue-card {sev_class}" data-category="{iss.category.value}" data-severity="{iss.severity.value}">
                <div class="card-header">
                    <span class="badge {sev_class}">{iss.severity.value}</span>
                    <span class="badge category">{cat_badge}</span>
                    {fixable_badge}
                    <span class="rule-id">{html.escape(iss.rule_id)}</span>
                    <span class="file-loc">{html.escape(iss.file_path)}:{iss.line_number}</span>
                </div>
                <h3>{html.escape(iss.title)}</h3>
                <p class="desc">{html.escape(iss.description)}</p>
                {snippet_html}
                <div class="fix-box">
                    <strong>Recommended Fix:</strong> {html.escape(iss.suggested_fix)}
                </div>
            </div>
            """)

        # Build insight cards
        insight_cards = []
        for ins in report.insights:
            badge_class = ins.risk_level.lower()
            insight_cards.append(f"""
            <div class="insight-card {badge_class}">
                <div class="insight-header">
                    <span class="badge {badge_class}">{ins.risk_level}</span>
                    <h4>{html.escape(ins.headline)}</h4>
                </div>
                <p><strong>Impact:</strong> {html.escape(ins.impact)}</p>
                <p class="action"><strong>Priority Action:</strong> {html.escape(ins.recommended_action)}</p>
            </div>
            """)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SlopSentinel - Codebase Health & Triage Report</title>
    <style>
        :root {{
            --bg: #0d1117;
            --surface: #161b22;
            --border: #30363d;
            --text: #c9d1d9;
            --text-bright: #f0f6fc;
            --critical: #f85149;
            --high: #d29922;
            --medium: #58a6ff;
            --low: #8b949e;
            --green: #2ea043;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }}
        body {{ background: var(--bg); color: var(--text); padding: 2rem; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{ margin-bottom: 2rem; border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem; }}
        h1 {{ color: var(--text-bright); font-size: 1.8rem; display: flex; align-items: center; gap: 0.5rem; }}
        .score-box {{ background: var(--surface); border: 2px solid var(--border); border-radius: 12px; padding: 1rem 1.5rem; text-align: center; }}
        .score {{ font-size: 2.2rem; font-weight: bold; color: {("#2ea043" if s.health_score >= 80 else ("#d29922" if s.health_score >= 50 else "#f85149"))}; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
        .stat-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; text-align: center; }}
        .stat-num {{ font-size: 1.8rem; font-weight: bold; color: var(--text-bright); margin-top: 0.3rem; }}
        .badge {{ padding: 0.2rem 0.6rem; border-radius: 12px; font-size: 0.75rem; font-weight: bold; text-transform: uppercase; }}
        .badge.critical {{ background: rgba(248, 81, 73, 0.2); color: var(--critical); border: 1px solid var(--critical); }}
        .badge.high {{ background: rgba(210, 153, 34, 0.2); color: var(--high); border: 1px solid var(--high); }}
        .badge.medium {{ background: rgba(88, 166, 255, 0.2); color: var(--medium); border: 1px solid var(--medium); }}
        .badge.low, .badge.info {{ background: rgba(139, 148, 158, 0.2); color: var(--low); border: 1px solid var(--low); }}
        .badge.category {{ background: #21262d; color: var(--text-bright); }}
        .badge.fixable {{ background: rgba(46, 160, 67, 0.2); color: var(--green); border: 1px solid var(--green); }}
        .section-title {{ font-size: 1.4rem; color: var(--text-bright); margin: 2rem 0 1rem; display: flex; align-items: center; justify-content: space-between; }}
        .insights-list {{ display: flex; flex-direction: column; gap: 1rem; margin-bottom: 2rem; }}
        .insight-card {{ background: var(--surface); border: 1px solid var(--border); border-left: 4px solid var(--border); border-radius: 8px; padding: 1rem; }}
        .insight-card.critical {{ border-left-color: var(--critical); }}
        .insight-card.high {{ border-left-color: var(--high); }}
        .insight-card.medium {{ border-left-color: var(--medium); }}
        .insight-header {{ display: flex; align-items: center; gap: 0.8rem; margin-bottom: 0.5rem; }}
        .insight-card h4 {{ color: var(--text-bright); font-size: 1.1rem; }}
        .insight-card p {{ margin: 0.3rem 0; font-size: 0.9rem; }}
        .insight-card .action {{ color: var(--green); }}
        .controls {{ display: flex; gap: 1rem; margin-bottom: 1.5rem; flex-wrap: wrap; }}
        .filter-btn {{ background: var(--surface); border: 1px solid var(--border); color: var(--text); padding: 0.5rem 1rem; border-radius: 6px; cursor: pointer; transition: 0.2s; }}
        .filter-btn:hover, .filter-btn.active {{ background: #21262d; border-color: var(--medium); color: var(--text-bright); }}
        .issue-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1.2rem; margin-bottom: 1rem; }}
        .issue-card.critical {{ border-left: 4px solid var(--critical); }}
        .issue-card.high {{ border-left: 4px solid var(--high); }}
        .issue-card.medium {{ border-left: 4px solid var(--medium); }}
        .issue-card.low {{ border-left: 4px solid var(--low); }}
        .card-header {{ display: flex; align-items: center; gap: 0.6rem; margin-bottom: 0.6rem; flex-wrap: wrap; }}
        .rule-id {{ color: var(--low); font-size: 0.8rem; font-mono: monospace; }}
        .file-loc {{ font-family: monospace; color: var(--medium); font-size: 0.85rem; margin-left: auto; }}
        .issue-card h3 {{ color: var(--text-bright); font-size: 1.1rem; margin-bottom: 0.4rem; }}
        .issue-card .desc {{ font-size: 0.9rem; margin-bottom: 0.8rem; }}
        pre {{ background: #090d13; padding: 0.8rem; border-radius: 6px; overflow-x: auto; font-size: 0.85rem; margin-bottom: 0.8rem; border: 1px solid #21262d; }}
        .fix-box {{ background: rgba(46, 160, 67, 0.1); border: 1px solid rgba(46, 160, 67, 0.3); padding: 0.8rem; border-radius: 6px; font-size: 0.85rem; color: #7ee787; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>🛡️ SlopSentinel Triage Report</h1>
                <p style="color: var(--low); margin-top: 0.4rem;">Architecture-Agnostic Anti-Slop & Security Intelligence Agent</p>
                <p style="font-size: 0.85rem; color: var(--low); margin-top: 0.2rem;">Generated: {report.timestamp} | Target: {html.escape(report.project_root)}</p>
            </div>
            <div class="score-box">
                <div style="font-size: 0.8rem; color: var(--low); text-transform: uppercase;">Codebase Health</div>
                <div class="score">{s.health_score}</div>
                <div style="font-size: 0.85rem; font-weight: bold; color: var(--text-bright);">{grade}</div>
            </div>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <div>Files Scanned</div>
                <div class="stat-num">{s.files_scanned}</div>
            </div>
            <div class="stat-card">
                <div>Lines of Code</div>
                <div class="stat-num">{s.lines_scanned:,}</div>
            </div>
            <div class="stat-card">
                <div style="color: var(--critical);">Critical / High</div>
                <div class="stat-num" style="color: var(--critical);">{s.issues_by_severity.get('CRITICAL', 0) + s.issues_by_severity.get('HIGH', 0)}</div>
            </div>
            <div class="stat-card">
                <div style="color: var(--high);">AI Slop Issues</div>
                <div class="stat-num" style="color: var(--high);">{s.issues_by_category.get('SLOP', 0)}</div>
            </div>
            <div class="stat-card">
                <div style="color: var(--medium);">Coding Gaps</div>
                <div class="stat-num" style="color: var(--medium);">{s.issues_by_category.get('GAPS', 0)}</div>
            </div>
            <div class="stat-card">
                <div style="color: var(--green);">Auto-Fixable</div>
                <div class="stat-num" style="color: var(--green);">{report.remediations_available}</div>
            </div>
        </div>

        <div class="section-title">
            <span>Executive Triage Insights</span>
        </div>
        <div class="insights-list">
            {''.join(insight_cards) if insight_cards else '<p style="color: var(--low);">No active risk insights.</p>'}
        </div>

        <div class="section-title">
            <span>Detected Findings ({len(report.issues)})</span>
        </div>

        <div class="controls">
            <button class="filter-btn active" onclick="filterIssues('ALL')">All ({len(report.issues)})</button>
            <button class="filter-btn" onclick="filterIssues('SECURITY')">🛡️ Security ({s.issues_by_category.get('SECURITY', 0)})</button>
            <button class="filter-btn" onclick="filterIssues('SLOP')">🧹 AI Slop ({s.issues_by_category.get('SLOP', 0)})</button>
            <button class="filter-btn" onclick="filterIssues('GAPS')">🔍 Gaps ({s.issues_by_category.get('GAPS', 0)})</button>
            <button class="filter-btn" onclick="filterIssues('CRITICAL')">🚨 Critical ({s.issues_by_severity.get('CRITICAL', 0)})</button>
        </div>

        <div id="issues-container">
            {''.join(issue_cards) if issue_cards else '<p style="color: var(--green);">🎉 Perfect score! No issues detected.</p>'}
        </div>
    </div>

    <script>
        function filterIssues(tag) {{
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            event.target.classList.add('active');

            const cards = document.querySelectorAll('.issue-card');
            cards.forEach(card => {{
                if (tag === 'ALL') {{
                    card.style.display = 'block';
                }} else if (tag === 'CRITICAL') {{
                    card.style.display = card.getAttribute('data-severity') === 'CRITICAL' ? 'block' : 'none';
                }} else {{
                    card.style.display = card.getAttribute('data-category') === tag ? 'block' : 'none';
                }}
            }});
        }}
    </script>
</body>
</html>
"""
