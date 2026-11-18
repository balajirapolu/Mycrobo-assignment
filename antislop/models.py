"""
Data models and schemas for SlopSentinel.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Optional, Any
import json


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Category(str, Enum):
    SECURITY = "SECURITY"
    SLOP = "SLOP"
    GAPS = "GAPS"


@dataclass
class Issue:
    id: str
    file_path: str
    line_number: int
    rule_id: str
    title: str
    description: str
    severity: Severity
    category: Category
    code_snippet: str = ""
    suggested_fix: str = ""
    confidence: float = 1.0  # 0.0 to 1.0
    auto_fixable: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["category"] = self.category.value
        return d


@dataclass
class ScanSummary:
    files_scanned: int = 0
    lines_scanned: int = 0
    duration_seconds: float = 0.0
    issues_by_severity: Dict[str, int] = field(default_factory=lambda: {
        Severity.CRITICAL.value: 0,
        Severity.HIGH.value: 0,
        Severity.MEDIUM.value: 0,
        Severity.LOW.value: 0,
        Severity.INFO.value: 0,
    })
    issues_by_category: Dict[str, int] = field(default_factory=lambda: {
        Category.SECURITY.value: 0,
        Category.SLOP.value: 0,
        Category.GAPS.value: 0,
    })
    health_score: float = 100.0  # 0 to 100 scale

    def compute_health_score(self, total_issues: int) -> float:
        """
        Deducts points based on severity weights:
        CRITICAL: -15 pts
        HIGH: -7 pts
        MEDIUM: -3 pts
        LOW: -1 pt
        Normalized per 1000 lines of code or raw deductions with a floor of 0.
        """
        deductions = (
            self.issues_by_severity[Severity.CRITICAL.value] * 15.0 +
            self.issues_by_severity[Severity.HIGH.value] * 7.0 +
            self.issues_by_severity[Severity.MEDIUM.value] * 3.0 +
            self.issues_by_severity[Severity.LOW.value] * 1.0
        )
        self.health_score = max(0.0, round(100.0 - deductions, 1))
        return self.health_score


@dataclass
class TriageInsight:
    headline: str
    risk_level: str
    impact: str
    recommended_action: str
    affected_files: List[str] = field(default_factory=list)


@dataclass
class TriageReport:
    project_root: str
    timestamp: str
    summary: ScanSummary
    issues: List[Issue] = field(default_factory=list)
    insights: List[TriageInsight] = field(default_factory=list)
    remediations_available: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "project_root": self.project_root,
            "timestamp": self.timestamp,
            "summary": asdict(self.summary),
            "issues": [issue.to_dict() for issue in self.issues],
            "insights": [asdict(insight) for insight in self.insights],
            "remediations_available": self.remediations_available,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
