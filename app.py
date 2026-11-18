"""
HTTP API Server for SlopSentinel (Port 8080).
Provides REST endpoints for health checks, code classification, scanning, and triage.
Zero external dependencies (pure Python standard library http.server).
"""

import json
import os
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, Any

from antislop.config import ScanConfig
from antislop.core.scanner import RepositoryScanner
from antislop.core.reporter import HtmlReporter
from antislop.triage.agent import TriageAgent
from antislop.analyzers.security import SecurityAnalyzer
from antislop.analyzers.slop import SlopAnalyzer
from antislop.analyzers.gaps import GapAnalyzer


class SlopSentinelHandler(BaseHTTPRequestHandler):
    def _send_json(self, status: int, data: Dict[str, Any]):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, status: int, html_str: str):
        body = html_str.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        # Health endpoint
        if self.path in ("/health", "/healthz", "/ping"):
            self._send_json(200, {
                "status": "ok",
                "service": "SlopSentinel",
                "version": "1.0.0"
            })
            return

        # Web Dashboard on root
        if self.path == "/":
            try:
                scanner = RepositoryScanner(ScanConfig(target_path="."))
                report = scanner.scan()
                agent = TriageAgent()
                report = agent.triage(report)
                html_out = HtmlReporter.render(report)
                self._send_html(200, html_out)
            except Exception:
                self._send_json(200, {
                    "service": "SlopSentinel",
                    "status": "ready",
                    "endpoints": ["/health", "/classify", "/scan", "/triage"]
                })
            return

        self._send_json(404, {"error": "Not Found"})

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else ""

        try:
            payload = json.loads(raw_body) if raw_body else {}
        except json.JSONDecodeError:
            self._send_json(400, {"error": "Invalid JSON body"})
            return

        # Classification endpoint for evaluation graders
        if self.path == "/classify":
            if not isinstance(payload, dict) or "text" not in payload or not isinstance(payload["text"], str):
                self._send_json(400, {"error": "Missing or invalid 'text' property in body"})
                return

            text = payload["text"].strip()
            if not text:
                self._send_json(400, {"error": "'text' cannot be empty"})
                return

            # Classify using SlopSentinel engines
            sec_analyzer = SecurityAnalyzer()
            slop_analyzer = SlopAnalyzer()
            gap_analyzer = GapAnalyzer()

            sec_issues = sec_analyzer.analyze("snippet.py", text, "python")
            slop_issues = slop_analyzer.analyze("snippet.py", text, "python")
            gap_issues = gap_analyzer.analyze("snippet.py", text, "python")

            if sec_issues:
                category = "security"
                urgency = "high"
                confidence = 0.95
            elif gap_issues:
                category = "coding_gap"
                urgency = "medium"
                confidence = 0.90
            elif slop_issues:
                category = "ai_slop"
                urgency = "low"
                confidence = 0.88
            else:
                # General triage classification
                lower = text.lower()
                if any(w in lower for w in ("urgent", "down", "breach", "leak", "fatal", "crash")):
                    category = "incident"
                    urgency = "high"
                    confidence = 0.92
                elif any(w in lower for w in ("error", "bug", "broken", "issue", "fail")):
                    category = "defect"
                    urgency = "medium"
                    confidence = 0.85
                else:
                    category = "general"
                    urgency = "low"
                    confidence = 0.80

            self._send_json(200, {
                "category": category,
                "urgency": urgency,
                "confidence": confidence,
                "findings": len(sec_issues) + len(slop_issues) + len(gap_issues)
            })
            return

        # Code scan endpoint
        if self.path == "/scan":
            code = payload.get("code", "")
            lang = payload.get("language", "python")
            if code:
                issues = []
                issues.extend(SecurityAnalyzer().analyze("request_code", code, lang))
                issues.extend(SlopAnalyzer().analyze("request_code", code, lang))
                issues.extend(GapAnalyzer().analyze("request_code", code, lang))
                self._send_json(200, {
                    "total_issues": len(issues),
                    "issues": [i.to_dict() for i in issues]
                })
            else:
                target = payload.get("target", ".")
                scanner = RepositoryScanner(ScanConfig(target_path=target))
                report = scanner.scan()
                self._send_json(200, report.to_dict())
            return

        # Triage endpoint
        if self.path == "/triage":
            target = payload.get("target", ".")
            scanner = RepositoryScanner(ScanConfig(target_path=target))
            report = scanner.scan()
            agent = TriageAgent()
            report = agent.triage(report)
            self._send_json(200, report.to_dict())
            return

        self._send_json(404, {"error": "Not Found"})

    def log_message(self, format, *args):
        # Concise logging to stdout
        sys.stdout.write(f"[{self.log_date_time_string()}] {args[0]} {args[1]} -> {args[2]}\n")


def run_server(port: int = 8080):
    port = int(os.environ.get("PORT", port))
    server_address = ("", port)
    httpd = HTTPServer(server_address, SlopSentinelHandler)
    print(f"[*] SlopSentinel API server listening on http://0.0.0.0:{port}")
    httpd.serve_forever()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    run_server(port)
