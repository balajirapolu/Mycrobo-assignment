"""
Tests for security analyzer and secret detection.
"""

import unittest
from antislop.analyzers.security import SecurityAnalyzer, calculate_shannon_entropy
from antislop.models import Severity, Category


class TestSecurityAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = SecurityAnalyzer(entropy_threshold=4.0)

    def test_detect_openai_secret(self):
        code = 'client = OpenAI(api_key="sk-abcdefghijklmnopqrstuvwxyz1234567890abcdef")'
        issues = self.analyzer.analyze("test_api.py", code, "python")
        self.assertTrue(any("SEC-001" in i.rule_id or "SEC-010" in i.rule_id for i in issues))
        self.assertEqual(issues[0].category, Category.SECURITY)

    def test_detect_github_token(self):
        code = 'token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"'
        issues = self.analyzer.analyze("deploy.py", code, "python")
        self.assertTrue(any("SEC-002" in i.rule_id for i in issues))

    def test_detect_eval_execution(self):
        code = 'user_expr = request.args.get("q")\nresult = eval(user_expr)'
        issues = self.analyzer.analyze("handler.py", code, "python")
        eval_issue = next((i for i in issues if i.rule_id == "SEC-020"), None)
        self.assertIsNotNone(eval_issue)
        self.assertEqual(eval_issue.severity, Severity.CRITICAL)

    def test_detect_disabled_ssl(self):
        code = 'response = requests.get("https://internal.service", verify=False)'
        issues = self.analyzer.analyze("client.py", code, "python")
        ssl_issue = next((i for i in issues if i.rule_id == "SEC-024"), None)
        self.assertIsNotNone(ssl_issue)
        self.assertEqual(ssl_issue.severity, Severity.HIGH)

    def test_shannon_entropy(self):
        low_entropy = "aaaaaaaaaaaaaaaaaaaa"
        high_entropy = "7x!B9#mK$2pL@8qZ&5vW"
        self.assertLess(calculate_shannon_entropy(low_entropy), 1.0)
        self.assertGreater(calculate_shannon_entropy(high_entropy), 3.5)


if __name__ == "__main__":
    unittest.main()
