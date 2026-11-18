"""
Tests for CLI invocation, scanner pipeline, and report rendering.
"""

import unittest
from antislop.config import ScanConfig
from antislop.core.scanner import RepositoryScanner
from antislop.core.reporter import ConsoleReporter, SarifReporter, HtmlReporter
from antislop.triage.agent import TriageAgent


class TestCliAndPipeline(unittest.TestCase):
    def test_pipeline_on_clean_target(self):
        config = ScanConfig(target_path="antislop")
        scanner = RepositoryScanner(config)
        report = scanner.scan()
        agent = TriageAgent()
        report = agent.triage(report)

        self.assertGreater(report.summary.files_scanned, 0)
        self.assertGreater(report.summary.lines_scanned, 0)
        self.assertGreaterEqual(report.summary.health_score, 0)

        # Ensure all formats render without exceptions
        console_out = ConsoleReporter.render(report)
        self.assertIn("SLOPSENTINEL", console_out)

        sarif_out = SarifReporter.render(report)
        self.assertIn("$schema", sarif_out)

        html_out = HtmlReporter.render(report)
        self.assertIn("<!DOCTYPE html>", html_out)


if __name__ == "__main__":
    unittest.main()
