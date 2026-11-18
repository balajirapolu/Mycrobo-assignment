"""
Tests for AI slop, phantom imports, and dead code detection.
"""

import unittest
from antislop.analyzers.slop import SlopAnalyzer
from antislop.models import Category, Severity


class TestSlopAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = SlopAnalyzer()

    def test_detect_ai_chat_artifact(self):
        code = """# Certainly! Here is the python implementation:
def compute_sum(a, b):
    return a + b
"""
        issues = self.analyzer.analyze("math_service.py", code, "python")
        artifact_issue = next((i for i in issues if i.rule_id == "SLOP-001"), None)
        self.assertIsNotNone(artifact_issue)
        self.assertEqual(artifact_issue.category, Category.SLOP)

    def test_detect_ghost_import(self):
        code = """import os
import math
import sys

def print_name(name):
    print(name)
"""
        issues = self.analyzer.analyze("names.py", code, "python")
        ghost_rules = [i for i in issues if i.rule_id == "SLOP-010"]
        self.assertGreaterEqual(len(ghost_rules), 2)  # os, math, sys unused

    def test_detect_empty_stub_function(self):
        code = """def process_payments(user, amount):
    '''Processes user payment transaction'''
    pass
"""
        issues = self.analyzer.analyze("billing.py", code, "python")
        stub_issue = next((i for i in issues if i.rule_id == "SLOP-011"), None)
        self.assertIsNotNone(stub_issue)
        self.assertEqual(stub_issue.category, Category.SLOP)

    def test_detect_tautological_wrapper(self):
        code = """def identity_pass(val):
    return val
"""
        issues = self.analyzer.analyze("wrappers.py", code, "python")
        taut_issue = next((i for i in issues if i.rule_id == "SLOP-012"), None)
        self.assertIsNotNone(taut_issue)


if __name__ == "__main__":
    unittest.main()
