"""Tool fingerprinting engine.

Identifies scanners, exploit frameworks, and manual recon by analyzing
request signatures, header patterns, and behavioral tells.
"""

import hashlib
import re
from typing import Optional


HEADER_SIGNATURES = {
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
    "python-requests": lambda h: h.get("user-agent", "").startswith("python-requests/"),
    "python-urllib": lambda h: h.get("user-agent", "").startswith("Python-urllib/"),
    "go-http": lambda h: h.get("user-agent", "").startswith("Go-http-client/"),
    "curl": lambda h: h.get("user-agent", "").startswith("curl/"),
    "wget": lambda h: h.get("user-agent", "").startswith("Wget/"),
    "httpie": lambda h: h.get("user-agent", "").startswith("HTTPie/"),
    "powershell": lambda h: "windowspowershell" in h.get("user-agent", "").lower().replace(" ", ""),
    "metasploit": lambda h: "metasploit" in h.get("user-agent", "").lower() or
                            "msf" in h.get("user-agent", "").lower(),
    "empty-ua": lambda h: h.get("user-agent", "") == "",
    "missing-ua": lambda h: "user-agent" not in h,
}


def fingerprint_request(headers: dict) -> str:
    headers_lower = {k.lower(): v for k, v in headers.items()}
    for tool_name, detector in HEADER_SIGNATURES.items():
        try:
            if detector(headers_lower):
                return tool_name
        except Exception:
            continue
    return "unknown"


def compute_attacker_fingerprint(
    source_ip: str, user_agent: str,
    accept_lang: str = "", accept_encoding: str = "",
) -> str:
    raw = "|".join([source_ip, user_agent, accept_lang, accept_encoding])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def detect_injection_attempt(path: str, body: str, query_string: str) -> Optional[str]:
    patterns = [
        r"['\"].*(?:OR|AND|UNION|SELECT|DROP|INSERT|UPDATE|DELETE)",
        r"<script[^>]*>",
        r"\.\./\.\./",
        r"%00", r"\x00", r"{{.*}}", r"\$\{.*\}",
    ]
    combined = f"{path} {body} {query_string}"
    for pattern in patterns:
        if re.search(pattern, combined, re.IGNORECASE):
            return "injection-attempt"
    return None
