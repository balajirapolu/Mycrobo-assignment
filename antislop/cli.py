"""
Command Line Interface (CLI) for SlopSentinel.
Supports scan, triage, fix, and report generation subcommands.
"""

import sys
import argparse
from pathlib import Path

from antislop.config import ScanConfig
from antislop.core.scanner import RepositoryScanner
from antislop.core.reporter import ConsoleReporter, SarifReporter, HtmlReporter
from antislop.triage.agent import TriageAgent
from antislop.triage.remediation import RemediationEngine
from antislop.models import Severity


def main():
    parser = argparse.ArgumentParser(
        prog="antislop",
        description="SlopSentinel: Architecture-Agnostic Anti-Slop, Security & Code Gap Triage Agent."
    )
    subparsers = parser.add_subparsers(dest="command", help="Subcommand to execute")

    # Command: scan
    scan_parser = subparsers.add_parser("scan", help="Scan repository for security vulnerabilities, AI slop, and gaps.")
    scan_parser.add_argument("target", nargs="?", default=".", help="Target directory or file (default: current directory)")
    scan_parser.add_argument("--format", choices=["console", "json", "sarif", "html"], default="console", help="Output format")
    scan_parser.add_argument("--out", "-o", default="", help="File path to write output (e.g. report.html)")
    scan_parser.add_argument("--ci", action="store_true", help="CI/CD mode: Exit with code 1 if Critical or High issues exist")
    scan_parser.add_argument("--strict", action="store_true", help="Strict mode: Exit with code 1 on Medium issues too")
    scan_parser.add_argument("--entropy", type=float, default=4.2, help="Entropy threshold for secret scanning")

    # Command: triage
    triage_parser = subparsers.add_parser("triage", help="Generate executive AI triage insights and risk roadmap.")
    triage_parser.add_argument("target", nargs="?", default=".", help="Target directory or file")

    # Command: fix
    fix_parser = subparsers.add_parser("fix", help="Generate or apply automated patches for fixable issues.")
    fix_parser.add_argument("target", nargs="?", default=".", help="Target directory or file")
    fix_parser.add_argument("--dry-run", action="store_true", default=True, help="Preview diffs without writing (default)")
    fix_parser.add_argument("--apply", action="store_true", help="Apply fixes directly in-place to files")

    # Command: dashboard
    dash_parser = subparsers.add_parser("dashboard", help="Generate an interactive standalone HTML dashboard.")
    dash_parser.add_argument("target", nargs="?", default=".", help="Target directory or file")
    dash_parser.add_argument("--out", "-o", default="slop-dashboard.html", help="Dashboard HTML output file")

    args = parser.parse_args()

    # Default to 'scan' if no command provided
    if not args.command:
        args.command = "scan"
        args.target = "."
        args.format = "console"
        args.out = ""
        args.ci = False
        args.strict = False
        args.entropy = 4.2

    target_dir = getattr(args, "target", ".")
    config = ScanConfig(target_path=target_dir)

    if hasattr(args, "entropy"):
        config.entropy_threshold = args.entropy

    scanner = RepositoryScanner(config)
    report = scanner.scan()

    agent = TriageAgent()
    report = agent.triage(report)

    if args.command == "scan":
        fmt = getattr(args, "format", "console")
        out_file = getattr(args, "out", "")

        rendered = ""
        if fmt == "console":
            rendered = ConsoleReporter.render(report)
        elif fmt == "json":
            rendered = report.to_json()
        elif fmt == "sarif":
            rendered = SarifReporter.render(report)
        elif fmt == "html":
            rendered = HtmlReporter.render(report)

        if out_file:
            Path(out_file).write_text(rendered, encoding="utf-8")
            print(f"Report successfully saved to {out_file}")
        else:
            print(rendered)

        # CI exit code handling
        if getattr(args, "ci", False):
            crit = report.summary.issues_by_severity.get("CRITICAL", 0)
            high = report.summary.issues_by_severity.get("HIGH", 0)
            med = report.summary.issues_by_severity.get("MEDIUM", 0)

            if crit > 0 or high > 0:
                print(f"\n[CI FAILURE] Found {crit} Critical and {high} High severity issues.")
                sys.exit(1)
            if getattr(args, "strict", False) and med > 0:
                print(f"\n[CI FAILURE] Found {med} Medium severity issues in strict mode.")
                sys.exit(1)

    elif args.command == "triage":
        print(ConsoleReporter.render(report))

    elif args.command == "dashboard":
        out_file = getattr(args, "out", "slop-dashboard.html")
        html_content = HtmlReporter.render(report)
        Path(out_file).write_text(html_content, encoding="utf-8")
        print(f"\n[+] Interactive HTML Dashboard generated at: {Path(out_file).resolve()}")
        print(f"[+] Open it in any browser to inspect issues and charts.\n")

    elif args.command == "fix":
        engine = RemediationEngine()
        patches = engine.generate_patches(report)

        if not patches:
            print("No auto-fixable issues detected in target.")
            return

        print(f"\nFound {len(patches)} file(s) with automated fixes available:\n")
        for file_path, (_, _, diff) in patches.items():
            print(f"--- Diff for {file_path} ---")
            print(diff or "No text changes")

        if getattr(args, "apply", False):
            count = engine.apply_patches(patches, report.project_root)
            print(f"\n[+] Successfully applied fixes to {count} file(s).")
        else:
            print("\nRun 'antislop fix --apply' to commit these changes to your codebase.")


if __name__ == "__main__":
    main()
