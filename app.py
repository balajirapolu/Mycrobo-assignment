"""
SlopSentinel Production API Server (Port 8080).
Architecture-Agnostic Anti-Slop, Security & Code Gap Triage Engine.

Features:
- Full support for 'ai-triage' Arena track specification
- In-memory rate limiting with 429 Too Many Requests & rate limit headers
- Security headers (X-Content-Type-Options: nosniff, X-Frame-Options: DENY)
- Strict payload size limits (1B - 16KB) returning 413
- High-precision classification (billing, technical, account, security, slop, general)
- Urgency analysis (high / low) and confidence scoring
- Endpoints: /health, /classify, /scan, /triage, /
"""

import json
import os
import sys
import time
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, Any, Tuple

from antislop.analyzers.security import SecurityAnalyzer
from antislop.analyzers.slop import SlopAnalyzer
from antislop.analyzers.gaps import GapAnalyzer
from antislop.core.scanner import RepositoryScanner
from antislop.core.reporter import HtmlReporter
from antislop.triage.agent import TriageAgent
from antislop.config import ScanConfig


# --- Rate Limiter ---
class RateLimiter:
    """Sliding window rate limiter per client IP."""
    def __init__(self, max_requests: int = 120, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(list)

    def is_allowed(self, client_ip: str) -> Tuple[bool, int, int]:
        """Returns (allowed, remaining_requests, reset_seconds)."""
        now = time.time()
        window_start = now - self.window_seconds
        # Clean expired timestamps
        self.requests[client_ip] = [t for t in self.requests[client_ip] if t > window_start]
        count = len(self.requests[client_ip])

        if count >= self.max_requests:
            oldest = self.requests[client_ip][0]
            reset_sec = max(1, int(oldest + self.window_seconds - now))
            return False, 0, reset_sec

        self.requests[client_ip].append(now)
        remaining = max(0, self.max_requests - (count + 1))
        return True, remaining, self.window_seconds


rate_limiter = RateLimiter(max_requests=120, window_seconds=60)


# --- Core Triage & Classification Engine ---
import re

CLASSIFICATION_RULES = (
    ("security", (
        "secret", "api key", "token", "leak", "exposed", "vulnerability",
        "injection", "sqli", "xss", "eval", "cve", "exploit", "rce", "backdoor",
        "private key", "unauthorized", "bypass", "unencrypted", "credential", "breach"
    )),
    ("billing", (
        "refund", "invoice", "payment", "pay", "charge", "fee", "receipt",
        "bill", "subscription", "cancel", "renewal", "credit card", "stripe",
        "pricing", "cost", "charged", "overcharge", "transaction"
    )),
    ("technical", (
        "error", "crash", "bug", "broken", "issue", "exception", "traceback",
        "fail", "failure", "glitch", "freeze", "500", "timeout", "down",
        "outage", "stacktrace", "syntax", "null pointer", "undefined", "corrupt"
    )),
    ("account", (
        "login", "log in", "sign in", "signin", "password", "account", "username",
        "reset password", "2fa", "mfa", "authenticate", "credentials",
        "profile", "lock", "register", "signup", "sign up", "session expired"
    )),
    ("slop", (
        "ghost import", "unused import", "ai slop", "boilerplate", "identity wrapper",
        "certainly! here is", "placeholder", "todo: implement", "dead code"
    )),
)

HIGH_URGENCY_KEYWORDS = (
    "urgent", "outage", "immediately", "emergency", "critical", "asap",
    "fatal", "down", "breach", "disaster", "blocker", "severe", "production down"
)


def classify(text: str) -> Dict[str, Any]:
    """Classifies input text according to the ai-triage track criteria."""
    text_lower = text.lower()
    category = "general"
    matched_confidence = 0.60

    # Rule matching for domain classification with word boundaries
    for label, words in CLASSIFICATION_RULES:
        if any(re.search(r"\b" + re.escape(w) + r"\b", text_lower) for w in words):
            category = label
            matched_confidence = 0.85
            break

    # Deep code analysis if code snippet is detected
    if any(k in text for k in ("def ", "import ", "function ", "class ", "eval(", "except", "throw")):
        sec_issues = SecurityAnalyzer().analyze("snippet.py", text, "python")
        slop_issues = SlopAnalyzer().analyze("snippet.py", text, "python")
        gap_issues = GapAnalyzer().analyze("snippet.py", text, "python")

        if sec_issues:
            category = "security"
            matched_confidence = 0.95
        elif gap_issues:
            category = "technical"
            matched_confidence = 0.90
        elif slop_issues:
            category = "slop"
            matched_confidence = 0.88

    urgency = "high" if any(w in text_lower for w in HIGH_URGENCY_KEYWORDS) else "low"

    return {
        "category": category,
        "urgency": urgency,
        "confidence": matched_confidence
    }


# --- Request Handler ---
class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def _get_client_ip(self) -> str:
        forwarded = self.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return self.client_address[0] if self.client_address else "127.0.0.1"

    def reply(self, status: int, data: Dict[str, Any], extra_headers: Dict[str, str] = None):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Access-Control-Allow-Origin", "*")

        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, str(v))

        self.end_headers()
        self.wfile.write(body)

    def reply_html(self, status: int, html_str: str):
        body = html_str.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _check_rate_limit(self) -> bool:
        client_ip = self._get_client_ip()
        allowed, remaining, reset_sec = rate_limiter.is_allowed(client_ip)

        headers = {
            "X-RateLimit-Limit": str(rate_limiter.max_requests),
            "X-RateLimit-Remaining": str(remaining),
            "X-RateLimit-Reset": str(reset_sec)
        }

        if not allowed:
            headers["Retry-After"] = str(reset_sec)
            self.reply(429, {"error": "too_many_requests", "message": "Rate limit exceeded"}, headers)
            return False

        # Add headers to response tracking
        self._rate_limit_headers = headers
        return True

    def do_GET(self):
        # Health check endpoint (matches both {"ok": True} and {"status": "ok"})
        if self.path in ("/health", "/healthz", "/ping"):
            self.reply(200, {
                "ok": True,
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
                self.reply_html(200, html_out)
            except Exception:
                self.reply(200, {
                    "ok": True,
                    "service": "SlopSentinel",
                    "endpoints": ["/health", "/classify", "/scan", "/triage"]
                })
            return

        self.reply(404, {"error": "not_found"})

    def do_POST(self):
        # Apply rate limiting
        if not self._check_rate_limit():
            return

        # Check endpoints
        if self.path == "/classify":
            self._handle_classify()
        elif self.path == "/scan":
            self._handle_scan()
        elif self.path == "/triage":
            self._handle_triage()
        else:
            self.reply(404, {"error": "not_found"}, getattr(self, "_rate_limit_headers", None))

    def _handle_classify(self):
        headers = getattr(self, "_rate_limit_headers", None)
        try:
            size_str = self.headers.get("Content-Length", "0")
            size = int(size_str)
        except (ValueError, TypeError):
            self.reply(400, {"error": "invalid_length"}, headers)
            return

        # Strict body size checks matching Arena criteria (1 <= size <= 16384)
        if not (1 <= size <= 16384):
            self.reply(413, {"error": "body_size"}, headers)
            return

        try:
            raw_data = self.rfile.read(size)
            data = json.loads(raw_data)
        except (ValueError, UnicodeError, TimeoutError):
            self.reply(400, {"error": "invalid_json"}, headers)
            return

        if not isinstance(data, dict) or not isinstance(data.get("text"), str) or not data["text"].strip():
            self.reply(400, {"error": "text_required"}, headers)
            return

        result = classify(data["text"])
        self.reply(200, result, headers)

    def _handle_scan(self):
        headers = getattr(self, "_rate_limit_headers", None)
        try:
            size = int(self.headers.get("Content-Length", "0"))
            data = json.loads(self.rfile.read(size)) if size > 0 else {}
        except Exception:
            self.reply(400, {"error": "invalid_json"}, headers)
            return

        code = data.get("code", "")
        lang = data.get("language", "python")
        if code:
            issues = []
            issues.extend(SecurityAnalyzer().analyze("request_code", code, lang))
            issues.extend(SlopAnalyzer().analyze("request_code", code, lang))
            issues.extend(GapAnalyzer().analyze("request_code", code, lang))
            self.reply(200, {
                "total_issues": len(issues),
                "issues": [i.to_dict() for i in issues]
            }, headers)
        else:
            target = data.get("target", ".")
            report = RepositoryScanner(ScanConfig(target_path=target)).scan()
            self.reply(200, report.to_dict(), headers)

    def _handle_triage(self):
        headers = getattr(self, "_rate_limit_headers", None)
        try:
            size = int(self.headers.get("Content-Length", "0"))
            data = json.loads(self.rfile.read(size)) if size > 0 else {}
        except Exception:
            data = {}

        target = data.get("target", ".")
        report = RepositoryScanner(ScanConfig(target_path=target)).scan()
        agent = TriageAgent()
        report = agent.triage(report)
        self.reply(200, report.to_dict(), headers)

    def log_message(self, format, *args):
        # Do not log PII or raw request payloads
        pass


def run_server(port: int = 8080):
    port = int(os.environ.get("PORT", port))
    host = os.environ.get("HOST", "0.0.0.0")
    server = ThreadingHTTPServer((host, port), Handler)
    server.serve_forever()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    run_server(port)
