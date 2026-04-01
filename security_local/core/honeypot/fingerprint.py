"""Attacker tool fingerprinting engine.

Identifies scanning tools, exploit frameworks, and manual reconnaissance
by analyzing request signatures, header patterns, and behavioral tells.
Pure Python. Zero external dependencies.
"""

import hashlib
import json
import re
from typing import Optional


# Tool signature database - request patterns that identify specific tools.
# Each entry: (name, detection_function)
# These are matched against incoming requests to tag what the attacker is using.

HEADER_SIGNATURES = {
    # Automated scanners
    "nmap-http": lambda h: "nmap" in h.get("user-agent", "").lower(),
    "nikto": lambda h: "nikto" in h.get("user-agent", "").lower(),
    "sqlmap": lambda h: "sqlmap" in h.get("user-agent", "").lower(),
    "dirbuster": lambda h: "dirbuster" in h.get("user-agent", "").lower(),
    "gobuster": lambda h: "gobuster" in h.get("user-agent", "").lower(),
    "wfuzz": lambda h: "wfuzz" in h.get("user-agent", "").lower(),
    "ffuf": lambda h: "ffuf" in h.get("user-agent", "").lower(),
    "feroxbuster": lambda h: "feroxbuster" in h.get("user-agent", "").lower(),
    "nuclei": lambda h: "nuclei" in h.get("user-agent", "").lower(),
    "burpsuite": lambda h: "burp" in h.get("user-agent", "").lower(),
    "zaproxy": lambda h: "zap" in h.get("user-agent", "").lower(),

    # Language/library defaults
    "python-requests": lambda h: h.get("user-agent", "").startswith("python-requests/"),
    "python-urllib": lambda h: h.get("user-agent", "").startswith("Python-urllib/"),
    "go-http": lambda h: h.get("user-agent", "").startswith("Go-http-client/"),
    "curl": lambda h: h.get("user-agent", "").startswith("curl/"),
    "wget": lambda h: h.get("user-agent", "").startswith("Wget/"),
    "httpie": lambda h: h.get("user-agent", "").startswith("HTTPie/"),
    "powershell": lambda h: "windowspowershell" in h.get("user-agent", "").lower().replace(" ", ""),

    # Exploit frameworks
    "metasploit": lambda h: "metasploit" in h.get("user-agent", "").lower() or
                            "msf" in h.get("user-agent", "").lower(),
    "cobalt-strike": lambda h: _detect_cobalt_strike(h),

    # Empty or suspicious UA
    "empty-ua": lambda h: h.get("user-agent", "") == "",
    "missing-ua": lambda h: "user-agent" not in h,
}


# Behavioral patterns - detected across multiple requests
BEHAVIORAL_PATTERNS = {
    "directory-enumeration": {
        "description": "Rapid sequential requests to common paths",
        "paths": [
            "/admin", "/administrator", "/wp-admin", "/phpmyadmin",
            "/manager", "/console", "/.env", "/.git/config",
            "/wp-login.php", "/xmlrpc.php", "/api/v1", "/swagger",
            "/graphql", "/.well-known", "/robots.txt", "/sitemap.xml",
            "/backup", "/dump", "/db", "/database", "/config",
            "/secret", "/private", "/internal", "/debug",
        ],
    },
    "credential-stuffing": {
        "description": "Repeated login attempts with varying credentials",
        "threshold": 5,
    },
    "parameter-fuzzing": {
        "description": "Requests with injection payloads in parameters",
        "patterns": [
            r"['\"].*(?:OR|AND|UNION|SELECT|DROP|INSERT|UPDATE|DELETE)",
            r"<script[^>]*>",
            r"\.\./\.\./",
            r"%00",
            r"\x00",
            r"{{.*}}",
            r"\$\{.*\}",
        ],
    },
    "method-probing": {
        "description": "Unusual HTTP methods",
        "methods": ["TRACE", "CONNECT", "OPTIONS", "PROPFIND", "PATCH", "DELETE", "PUT"],
    },
}


def _detect_cobalt_strike(headers: dict) -> bool:
    """Detect Cobalt Strike beacon patterns in headers."""
    ua = headers.get("user-agent", "")
    # CS default malleable profiles often use specific patterns
    if re.match(r"^Mozilla/[45]\.0 \(compatible; MSIE \d+\.\d+;", ua):
        # Check for suspiciously minimal headers alongside IE UA
        header_count = len(headers)
        if header_count <= 4:
            return True
    return False


def fingerprint_request(headers: dict) -> str:
    """Identify the tool/method used for this request.

    Returns the most specific matching tool signature name,
    or 'unknown' if no signature matches.
    """
    headers_lower = {k.lower(): v for k, v in headers.items()}

    for tool_name, detector in HEADER_SIGNATURES.items():
        try:
            if detector(headers_lower):
                return tool_name
        except Exception:
            continue

    return "unknown"


def compute_attacker_fingerprint(
    source_ip: str,
    user_agent: str,
    accept_lang: str = "",
    accept_encoding: str = "",
) -> str:
    """Generate a stable fingerprint for an attacker session.

    Combines multiple signals to create a fingerprint that persists
    across requests but distinguishes different attackers from the
    same IP (e.g., different tools on the same box).
    """
    components = [
        source_ip,
        user_agent,
        accept_lang,
        accept_encoding,
    ]
    raw = "|".join(components)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def detect_injection_attempt(path: str, body: str, query_string: str) -> Optional[str]:
    """Check if request contains injection payloads.

    Returns the type of injection detected, or None.
    """
    combined = f"{path} {body} {query_string}"

    for pattern in BEHAVIORAL_PATTERNS["parameter-fuzzing"]["patterns"]:
        if re.search(pattern, combined, re.IGNORECASE):
            return "injection-attempt"

    return None


def analyze_request_timing(timestamps: list[float]) -> dict:
    """Analyze timing patterns in a sequence of request timestamps.

    Automated tools produce unnaturally regular intervals.
    Returns analysis dict with bot probability score.
    """
    if len(timestamps) < 3:
        return {"bot_probability": 0.0, "pattern": "insufficient-data"}

    intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
    avg_interval = sum(intervals) / len(intervals)

    if avg_interval == 0:
        return {"bot_probability": 1.0, "pattern": "zero-interval-burst"}

    # Calculate coefficient of variation - bots have low variance
    variance = sum((i - avg_interval) ** 2 for i in intervals) / len(intervals)
    std_dev = variance ** 0.5
    cv = std_dev / avg_interval if avg_interval > 0 else 0

    if cv < 0.05:
        return {"bot_probability": 0.95, "pattern": "machine-regular", "avg_interval_ms": avg_interval * 1000}
    elif cv < 0.15:
        return {"bot_probability": 0.7, "pattern": "likely-automated", "avg_interval_ms": avg_interval * 1000}
    elif cv < 0.4:
        return {"bot_probability": 0.3, "pattern": "mixed-signals", "avg_interval_ms": avg_interval * 1000}
    else:
        return {"bot_probability": 0.1, "pattern": "likely-human", "avg_interval_ms": avg_interval * 1000}


def build_tool_report(tool_sig: str, headers: dict, path: str, body: str) -> dict:
    """Build a comprehensive tool identification report."""
    headers_lower = {k.lower(): v for k, v in headers.items()}

    report = {
        "tool_signature": tool_sig,
        "user_agent_raw": headers_lower.get("user-agent", ""),
        "header_count": len(headers),
        "has_accept": "accept" in headers_lower,
        "has_accept_language": "accept-language" in headers_lower,
        "has_accept_encoding": "accept-encoding" in headers_lower,
        "has_referer": "referer" in headers_lower,
        "has_cookie": "cookie" in headers_lower,
        "has_origin": "origin" in headers_lower,
        "content_type": headers_lower.get("content-type", ""),
        "injection_detected": detect_injection_attempt(path, body, ""),
    }

    # Real browsers send a specific set of headers; scanners often don't
    browser_headers = {"accept", "accept-language", "accept-encoding"}
    present = browser_headers.intersection(set(headers_lower.keys()))
    report["browser_header_completeness"] = len(present) / len(browser_headers)

    return report
