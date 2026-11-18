"""
Tests for coding gaps, silent exception swallowers, and loose ends.
"""

import unittest
from antislop.analyzers.gaps import GapAnalyzer
from antislop.models import Category, Severity


class TestGapAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = GapAnalyzer()

    def test_detect_silent_except_pass(self):
        code = """try:
    connect_database()
except Exception:
    pass
"""
        issues = self.analyzer.analyze("db.py", code, "python")
        silent_issue = next((i for i in issues if i.rule_id == "GAP-010"), None)
        self.assertIsNotNone(silent_issue)
        self.assertEqual(silent_issue.category, Category.GAPS)
        self.assertEqual(silent_issue.severity, Severity.HIGH)

    def test_detect_unclosed_file_descriptor(self):
        code = """f = open("data.txt", "r")
content = f.read()
"""
        issues = self.analyzer.analyze("loader.py", code, "python")
        fd_issue = next((i for i in issues if i.rule_id == "GAP-020"), None)
        self.assertIsNotNone(fd_issue)
        self.assertEqual(fd_issue.category, Category.GAPS)

    def test_detect_unimplemented_stub(self):
        code = """def sync_records():
    raise NotImplementedError("Needs background worker implementation")
"""
        issues = self.analyzer.analyze("sync.py", code, "python")
        stub_issue = next((i for i in issues if i.rule_id == "GAP-030"), None)
        self.assertIsNotNone(stub_issue)
        self.assertEqual(stub_issue.severity, Severity.HIGH)

    def test_detect_unreachable_code(self):
        code = """def calc(a):
    return a * 2
    print("Done calculation")
"""
        issues = self.analyzer.analyze("calc.py", code, "python")
        dead_issue = next((i for i in issues if i.rule_id == "GAP-040"), None)
        self.assertIsNotNone(dead_issue)


if __name__ == "__main__":
    unittest.main()
