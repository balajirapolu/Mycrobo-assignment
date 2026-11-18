"""
Security scanner: High-entropy secret detection, injection risks, dynamic execution, and unsafe practices.
"""

import re
import math
from typing import List, Tuple
from antislop.models import Issue, Severity, Category

# Pre-compiled high-precision secret patterns
SECRET_PATTERNS = [
    ("SEC-001", "OpenAI / LLM API Key Exposed", Severity.CRITICAL,
     re.compile(r"""(?i)(?:sk-[a-zA-Z0-9]{24,}|sk-proj-[a-zA-Z0-9_\-]{20,}|sk-ant-[a-zA-Z0-9_\-]{30,}|AIza[0-9A-Za-z\-_]{35})""")),

    ("SEC-002", "GitHub Personal Access Token Exposed", Severity.CRITICAL,
     re.compile(r"""(?:ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})""")),

    ("SEC-003", "AWS Access Key or Secret Exposed", Severity.CRITICAL,
     re.compile(r"""(?:(A3T[A-Z0-9]|AKIA[0-9A-Z]{16})|aws_secret_access_key\s*=\s*['\"][A-Za-z0-9/+=]{40}['\"])""")),

    ("SEC-004", "Private Cryptographic Key in Code", Severity.CRITICAL,
     re.compile(r"""-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----""")),

    ("SEC-005", "Hardcoded Database Connection String with Credentials", Severity.HIGH,
     re.compile(r"""(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis):\/\/[a-zA-Z0-9_]+:[^@\s\n]+@[a-zA-Z0-9\.\-_]+""")),

    ("SEC-006", "Generic Leaked API Secret / Password Variable", Severity.HIGH,
     re.compile(r"""(?i)(?:api_key|secret_key|client_secret|db_password|access_token)\s*=\s*['\"][a-zA-Z0-9_\-\.]{16,}['\"]""")),

    ("SEC-007", "Slack / Discord Bot Token Exposed", Severity.HIGH,
     re.compile(r"""(?:xox[baprs]-[0-9a-zA-Z]{10,48}|https:\/\/discord\.com\/api\/webhooks\/[0-9]{18,19}\/[a-zA-Z0-9_\-]{60,})""")),

    ("SEC-008", "Stripe API Key Exposed", Severity.CRITICAL,
     re.compile(r"""(?:sk_live_[0-9a-zA-Z]{24}|rk_live_[0-9a-zA-Z]{24})""")),
]

# Vulnerable code patterns across polyglot languages
VULNERABILITY_PATTERNS = [
    ("SEC-020", "Arbitrary Dynamic Code Execution (eval/exec)", Severity.CRITICAL,
     re.compile(r"""(?<!\w)(?:eval|exec)\s*\((?!\s*['\"][^'\"]*['\"]\s*\))"""),
     "Avoid eval/exec on dynamic inputs; use structured parsers or safe dispatchers."),

    ("SEC-021", "Unsafe Shell Command Execution with shell=True", Severity.HIGH,
     re.compile(r"""subprocess\.(?:run|Popen|call|check_output)\s*\(.*shell\s*=\s*True.*\)"""),
     "Pass command arguments as an array and set shell=False to prevent command injection."),

    ("SEC-022", "Dangerous os.system Invocation", Severity.HIGH,
     re.compile(r"""os\.system\s*\((?!['\"][^%'\"]*['\"])"""),
     "Replace os.system with subprocess.run(['cmd', 'arg'], shell=False)."),

    ("SEC-023", "Potential SQL Injection via Raw String Formatting", Severity.HIGH,
     re.compile(r"""(?i)(?:execute|cursor\.execute)\s*\(\s*(?:f['\"].*(?:SELECT|INSERT|UPDATE|DELETE).*{.*}|['\"].*(?:SELECT|INSERT|UPDATE|DELETE).*%(?:s|d)|['\"].*(?:SELECT|INSERT|UPDATE|DELETE).*['\"]\s*\+)"""),
     "Use parameterized SQL queries (e.g. cursor.execute('SELECT * WHERE id = %s', (val,)))"),

    ("SEC-024", "Disabled SSL/TLS Certificate Verification", Severity.HIGH,
     re.compile(r"""(?i)(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0['\"]?)"""),
     "Enable SSL/TLS certificate verification to prevent man-in-the-middle attacks."),

    ("SEC-025", "Permissive Wildcard CORS with Credentials", Severity.MEDIUM,
     re.compile(r"""(?i)(?:Access-Control-Allow-Origin\s*:\s*\*\s*['\"]?.*credentials|allow_origins\s*=\s*\[\s*['\"]\*['\"]\s*\]\s*,\s*allow_credentials\s*=\s*True)"""),
     "Explicitly restrict allowed origins when credentials (cookies/auth) are supported."),

    ("SEC-026", "Weak Cryptographic Algorithm (MD5 / SHA1 for hashing)", Severity.MEDIUM,
     re.compile(r"""hashlib\.(?:md5|sha1)\s*\("""),
     "Use SHA-256 or bcrypt/argon2 for password and security sensitive hashing."),

    ("SEC-027", "Node.js Unsafe child_process.exec", Severity.HIGH,
     re.compile(r"""child_process\.exec\s*\(\s*`[^`]*\${"""),
     "Use child_process.execFile or execSync with array arguments instead of template literals in exec."),
]


def calculate_shannon_entropy(data: str) -> float:
    """Calculates the Shannon entropy of a string (in bits per byte)."""
    if not data:
        return 0.0
    entropy = 0.0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy += - p_x * math.log2(p_x)
    return entropy


class SecurityAnalyzer:
    """Detects security vulnerabilities, hardcoded secrets, and unsafe execution."""

    def __init__(self, entropy_threshold: float = 4.2):
        self.entropy_threshold = entropy_threshold

    def analyze(self, file_path: str, content: str, language: str) -> List[Issue]:
        issues: List[Issue] = []
        lines = content.splitlines()

        # Check for known secret patterns
        for line_idx, line in enumerate(lines, start=1):
            # Skip commented-out explanation lines in documentation or tests if appropriate
            stripped = line.strip()
            if not stripped or len(stripped) > 1000:
                continue

            # Check Secret Regexes
            for rule_id, title, severity, pattern in SECRET_PATTERNS:
                match = pattern.search(line)
                if match:
                    val = match.group(0)
                    masked = val[:4] + "*" * (len(val) - 8) + val[-4:] if len(val) > 10 else "****"
                    snippet = line.replace(val, masked).strip()
                    issues.append(Issue(
                        id=f"{rule_id}-{line_idx}",
                        file_path=file_path,
                        line_number=line_idx,
                        rule_id=rule_id,
                        title=title,
                        description=f"Exposed secret token detected on line {line_idx}. Do not commit credentials.",
                        severity=severity,
                        category=Category.SECURITY,
                        code_snippet=snippet,
                        suggested_fix="Move secret to an environment variable or secret manager (e.g., os.getenv('API_KEY')).",
                        confidence=0.98,
                        auto_fixable=True,
                        metadata={"rule_type": "secret_leak"}
                    ))

            # Check High Entropy strings in assignment statements (e.g. key = "238fnkwefj082...")
            self._check_entropy_leaks(line, line_idx, file_path, issues)

            # Check Vulnerable Code Patterns
            for rule_id, title, severity, pattern, fix in VULNERABILITY_PATTERNS:
                match = pattern.search(line)
                if match:
                    issues.append(Issue(
                        id=f"{rule_id}-{line_idx}",
                        file_path=file_path,
                        line_number=line_idx,
                        rule_id=rule_id,
                        title=title,
                        description=f"Potentially insecure execution pattern found: {match.group(0)[:60]}",
                        severity=severity,
                        category=Category.SECURITY,
                        code_snippet=line.strip()[:140],
                        suggested_fix=fix,
                        confidence=0.90,
                        auto_fixable=False,
                        metadata={"rule_type": "code_vulnerability"}
                    ))

        return issues

    def _check_entropy_leaks(self, line: str, line_idx: int, file_path: str, issues: List[Issue]):
        """Detects suspiciously high-entropy strings assigned to variables."""
        assignment_match = re.search(r"""(?:token|key|secret|pass|auth|jwt)\s*[:=]\s*['\"]([a-zA-Z0-9_\-\.\$\/]{24,})['\"]""", line, re.IGNORECASE)
        if assignment_match:
            candidate = assignment_match.group(1)
            entropy = calculate_shannon_entropy(candidate)
            if entropy >= self.entropy_threshold:
                # Avoid flagging already flagged patterns
                if any(iss.line_number == line_idx and iss.category == Category.SECURITY for iss in issues):
                    return
                masked = candidate[:3] + "..." + candidate[-3:]
                issues.append(Issue(
                    id=f"SEC-010-{line_idx}",
                    file_path=file_path,
                    line_number=line_idx,
                    rule_id="SEC-010",
                    title="High-Entropy Credential or Token Detected",
                    description=f"String has Shannon entropy {entropy:.2f} bits/byte, indicating an unencrypted secret.",
                    severity=Severity.HIGH,
                    category=Category.SECURITY,
                    code_snippet=line.replace(candidate, masked).strip()[:140],
                    suggested_fix="Store this secret in an environment variable or vault.",
                    confidence=0.88,
                    auto_fixable=True,
                    metadata={"entropy": entropy}
                ))
