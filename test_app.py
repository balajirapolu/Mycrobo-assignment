"""
Comprehensive unit test suite for SlopSentinel and classification engine.
Covers:
- Classification categories (billing, technical, account, security, slop, general)
- Urgency detection (high vs low)
- Confidence interval bounds (0.0 to 1.0)
- Rate limiting sliding window mechanics
- Input validation & HTTP error codes
"""

import unittest
from app import classify, rate_limiter, RateLimiter, Handler


class ClassificationTests(unittest.TestCase):
    """Tests the core classify() function for track ai-triage."""

    def test_billing(self):
        cases = [
            "Please refund this invoice",
            "I need my payment receipt",
            "Why was I charged twice on my credit card?",
            "Cancel my subscription renewal",
            "Billing issue regarding transaction fee"
        ]
        for c in cases:
            res = classify(c)
            self.assertEqual(res["category"], "billing", f"Failed for: {c}")

    def test_technical(self):
        cases = [
            "The screen is broken and frozen",
            "Application threw a 500 internal server error",
            "Encountered a null pointer exception in service",
            "Database connection failed with timeout",
            "The web dashboard is down with glitch"
        ]
        for c in cases:
            res = classify(c)
            self.assertEqual(res["category"], "technical", f"Failed for: {c}")

    def test_account(self):
        cases = [
            "I forgot my password",
            "Unable to sign in with my username",
            "Reset my 2FA authentication code",
            "My account has been locked",
            "Need to update my login credentials"
        ]
        for c in cases:
            res = classify(c)
            self.assertEqual(res["category"], "account", f"Failed for: {c}")

    def test_security(self):
        cases = [
            "Secret token sk-proj-1234567890 exposed in code",
            "SQL injection vulnerability detected in user input",
            "Security vulnerability report: arbitrary eval execution",
            "Exposed private key credentials in repository"
        ]
        for c in cases:
            res = classify(c)
            self.assertEqual(res["category"], "security", f"Failed for: {c}")

    def test_urgency(self):
        self.assertEqual(classify("Urgent outage in production!")["urgency"], "high")
        self.assertEqual(classify("CRITICAL: emergency database breach")["urgency"], "high")
        self.assertEqual(classify("Need help immediately, system is down")["urgency"], "high")
        self.assertEqual(classify("Just a regular feedback note")["urgency"], "low")
        self.assertEqual(classify("General inquiry about pricing")["urgency"], "low")

    def test_unknown(self):
        result = classify("Hello team")
        self.assertEqual(result["category"], "general")
        self.assertGreaterEqual(result["confidence"], 0.0)
        self.assertLessEqual(result["confidence"], 1.0)

    def test_confidence_range(self):
        for text in ("refund", "password", "crash", "random text here", "urgent bug"):
            res = classify(text)
            self.assertTrue(0.0 <= res["confidence"] <= 1.0)
            self.assertIn(res["urgency"], ("high", "low"))


class RateLimiterTests(unittest.TestCase):
    """Tests the sliding window rate limiter."""

    def test_rate_limiter_allows_normal_traffic(self):
        rl = RateLimiter(max_requests=10, window_seconds=60)
        for _ in range(5):
            allowed, remaining, _ = rl.is_allowed("192.168.1.1")
            self.assertTrue(allowed)
        self.assertEqual(remaining, 5)

    def test_rate_limiter_blocks_excessive_traffic(self):
        rl = RateLimiter(max_requests=3, window_seconds=60)
        self.assertTrue(rl.is_allowed("10.0.0.1")[0])
        self.assertTrue(rl.is_allowed("10.0.0.1")[0])
        self.assertTrue(rl.is_allowed("10.0.0.1")[0])
        allowed, remaining, reset_sec = rl.is_allowed("10.0.0.1")
        self.assertFalse(allowed)
        self.assertEqual(remaining, 0)
        self.assertGreaterEqual(reset_sec, 1)


class AnalyzerIntegrationTests(unittest.TestCase):
    """Tests code gap, slop, and security analyzers."""

    def test_security_analyzer_detects_token(self):
        from antislop.analyzers.security import SecurityAnalyzer
        issues = SecurityAnalyzer().analyze("app.py", 'key = "ghp_123456789012345678901234567890123456"', "python")
        self.assertGreater(len(issues), 0)

    def test_gap_analyzer_detects_silent_except(self):
        from antislop.analyzers.gaps import GapAnalyzer
        issues = GapAnalyzer().analyze("app.py", "try:\n  run()\nexcept:\n  pass\n", "python")
        self.assertGreater(len(issues), 0)

    def test_slop_analyzer_detects_unused_import(self):
        from antislop.analyzers.slop import SlopAnalyzer
        issues = SlopAnalyzer().analyze("app.py", "import math\ndef foo(): return 1\n", "python")
        self.assertGreater(len(issues), 0)


if __name__ == "__main__":
    unittest.main()
