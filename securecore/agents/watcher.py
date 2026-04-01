"""Watcher Agent - monitors ingress substrate for new hostile activity.

The watcher is the first-line interpreter. It watches the ingress
substrate and makes initial threat assessments:

  - Is this a known scanner signature?
  - Is this hitting known bait paths?
  - Is the request pattern consistent with enumeration?
  - Should a mirror cell be created or updated?

The watcher does NOT take action. It emits decisions that the control
plane and other agents (escalation, containment) can act on.
"""

import re
import time
from typing import Optional

from securecore.agents.base import Agent, AgentDecision
from securecore.substrates.base import Substrate, SubstrateRecord

# Known bait paths that indicate intentional probing
BAIT_PATHS = {
    "/admin", "/administrator", "/wp-admin", "/wp-login.php",
    "/phpmyadmin", "/console", "/manager",
    "/.env", "/.git/config", "/config", "/config.json",
    "/api/keys", "/api/tokens", "/credentials",
    "/api/users", "/dump", "/backup", "/database",
    "/robots.txt", "/sitemap.xml", "/swagger", "/swagger.json",
    "/graphql", "/xmlrpc.php", "/api-docs",
    "/status", "/info", "/version", "/server-status",
    "/network", "/internal", "/infrastructure",
    "/secret", "/private", "/debug",
}

SCANNER_USER_AGENTS = {
    "nmap", "nikto", "sqlmap", "dirbuster", "gobuster",
    "wfuzz", "ffuf", "feroxbuster", "nuclei", "burp", "zap",
    "metasploit", "msf",
}

INJECTION_PATTERNS = [
    r"['\"].*(?:OR|AND|UNION|SELECT|DROP|INSERT|UPDATE|DELETE)",
    r"<script[^>]*>",
    r"\.\./\.\./",
    r"%00",
    r"\$\{.*\}",
    r"{{.*}}",
]


class WatcherAgent(Agent):
    """First-line ingress monitor."""

    name = "watcher"

    def __init__(self, decision_substrate: Substrate):
        super().__init__(decision_substrate)
        self._ip_request_counts: dict[str, int] = {}
        self._ip_bait_hits: dict[str, int] = {}
        self._ip_first_seen: dict[str, float] = {}

    def consume(self, record: SubstrateRecord) -> None:
        """Process an ingress record and make initial threat assessment."""
        if record.substrate != "ingress" or record.record_type != "http_request":
            return

        p = record.payload
        source_ip = p.get("source_ip", "")
        path = p.get("path", "")
        method = p.get("method", "")
        user_agent = p.get("user_agent", "").lower()
        body_preview = p.get("body_preview", "")

        # Track IP activity
        self._ip_request_counts[source_ip] = self._ip_request_counts.get(source_ip, 0) + 1
        if source_ip not in self._ip_first_seen:
            self._ip_first_seen[source_ip] = time.time()

        # Check bait path hit
        path_clean = path.split("?")[0].rstrip("/").lower()
        is_bait = path_clean in BAIT_PATHS or any(path_clean.startswith(b) for b in BAIT_PATHS)

        if is_bait:
            self._ip_bait_hits[source_ip] = self._ip_bait_hits.get(source_ip, 0) + 1

        # Check scanner signature
        is_scanner = any(sig in user_agent for sig in SCANNER_USER_AGENTS)

        # Check injection
        combined = f"{path} {body_preview}"
        is_injection = any(re.search(pat, combined, re.IGNORECASE) for pat in INJECTION_PATTERNS)

        # Emit decisions based on findings
        if is_scanner:
            self.emit(AgentDecision(
                agent_name=self.name,
                decision_type="scanner_detected",
                confidence=0.9,
                cell_id=record.cell_id,
                reasoning=f"User-Agent matches known scanner pattern: {user_agent[:80]}",
                recommended_action="track",
                context={"source_ip": source_ip, "user_agent": user_agent, "path": path},
            ))

        if is_injection:
            self.emit(AgentDecision(
                agent_name=self.name,
                decision_type="injection_detected",
                confidence=0.95,
                cell_id=record.cell_id,
                reasoning=f"Injection payload detected in request to {path}",
                recommended_action="escalate",
                context={"source_ip": source_ip, "path": path, "method": method},
            ))

        bait_count = self._ip_bait_hits.get(source_ip, 0)
        if bait_count >= 3 and bait_count % 3 == 0:
            self.emit(AgentDecision(
                agent_name=self.name,
                decision_type="sustained_probing",
                confidence=0.85,
                cell_id=record.cell_id,
                reasoning=f"IP {source_ip} has hit {bait_count} bait paths",
                recommended_action="escalate",
                context={
                    "source_ip": source_ip,
                    "bait_hits": bait_count,
                    "total_requests": self._ip_request_counts[source_ip],
                },
            ))

        # Rapid-fire detection
        req_count = self._ip_request_counts[source_ip]
        elapsed = time.time() - self._ip_first_seen.get(source_ip, time.time())
        if req_count >= 20 and elapsed > 0 and (req_count / elapsed) > 5:
            self.emit(AgentDecision(
                agent_name=self.name,
                decision_type="rapid_fire",
                confidence=0.8,
                cell_id=record.cell_id,
                reasoning=f"IP {source_ip}: {req_count} requests in {elapsed:.1f}s ({req_count/elapsed:.1f}/s)",
                recommended_action="escalate",
                context={
                    "source_ip": source_ip,
                    "request_count": req_count,
                    "elapsed_seconds": round(elapsed, 1),
                    "rate_per_second": round(req_count / elapsed, 2),
                },
            ))

    def tick(self) -> None:
        """Periodic cleanup of stale IP tracking data."""
        now = time.time()
        stale_threshold = 3600  # 1 hour
        stale_ips = [
            ip for ip, first in self._ip_first_seen.items()
            if now - first > stale_threshold
        ]
        for ip in stale_ips:
            self._ip_request_counts.pop(ip, None)
            self._ip_bait_hits.pop(ip, None)
            self._ip_first_seen.pop(ip, None)
