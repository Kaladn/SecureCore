"""Mirror Cell Engine.

The core of the honeypot system. When an attacker hits a decoy endpoint,
a MirrorCell is spawned (or resumed) that locks onto their fingerprint.

The cell:
1. Tracks every request they make
2. Fingerprints their tools
3. Records forensic evidence with tamper-evident hash chains
4. Escalates threat level the deeper they probe
5. Mirrors back convincing fake data to keep them engaged
6. Builds a complete behavioral profile

Escalation levels:
  0 - OBSERVED:    First contact. Cell spawned. Watching.
  1 - TRACKING:    Multiple interactions. Pattern forming.
  2 - ENGAGED:     Active probing detected. Serving deeper decoys.
  3 - LOCKED:      Attacker is committed. Full forensic capture.
  4 - TRAPPED:     Extensive interaction. Routing forensics active.
  5 - BURNING:     Evidence package complete. They're cooked.

Once a cell reaches LOCKED (level 3), it never releases. The attacker
is in the system and every subsequent action strengthens the case.
"""

import hashlib
import json
import logging
import time
import threading
from datetime import datetime, UTC
from typing import Optional

from core.db import db
from core.models import MirrorCellRecord, ForensicEvidence
from core.honeypot.fingerprint import (
    compute_attacker_fingerprint,
    fingerprint_request,
    analyze_request_timing,
    detect_injection_attempt,
    build_tool_report,
)
from core.honeypot.forensics import record_evidence, emit_security_event
from core.honeypot.shun_engine import auto_shun_from_cell

logger = logging.getLogger("honeypot.mirror_cell")

ESCALATION_NAMES = {
    0: "OBSERVED",
    1: "TRACKING",
    2: "ENGAGED",
    3: "LOCKED",
    4: "TRAPPED",
    5: "BURNING",
}


class MirrorCell:
    """A live tracking cell for a single attacker session.

    Each cell maintains in-memory state for fast operation and
    persists critical data to the database for durability.
    """

    def __init__(self, cell_id: str, attacker_fingerprint: str, source_ip: str):
        self.cell_id = cell_id
        self.attacker_fingerprint = attacker_fingerprint
        self.source_ip = source_ip
        self.escalation_level = 0
        self.interaction_count = 0
        self.locked = False
        self.status = "tracking"
        self.first_seen = time.time()
        self.last_seen = time.time()
        self.request_timestamps: list[float] = []
        self.paths_visited: list[str] = []
        self.tools_seen: set[str] = set()
        self.injection_attempts: int = 0
        self._lock = threading.Lock()

    def process_request(
        self,
        method: str,
        path: str,
        headers: dict,
        body: str,
        source_ip: str,
        source_port: Optional[int],
        escalation_threshold: int = 3,
    ) -> dict:
        """Process an incoming request through this mirror cell.

        Records evidence, updates escalation, and returns metadata
        about how to respond (which decoy to serve, what to log).
        """
        with self._lock:
            now = time.time()
            self.last_seen = now
            self.interaction_count += 1
            self.request_timestamps.append(now)
            self.paths_visited.append(path)

            # Fingerprint the tool
            tool_sig = fingerprint_request(headers)
            self.tools_seen.add(tool_sig)

            # Check for injection attempts
            query_string = ""
            if "?" in path:
                query_string = path.split("?", 1)[1]
            injection = detect_injection_attempt(path, body, query_string)
            if injection:
                self.injection_attempts += 1

            # Determine evidence type
            evidence_type = self._classify_interaction(method, path, tool_sig, injection)

            # Escalate threat level
            old_level = self.escalation_level
            self._evaluate_escalation(escalation_threshold)

            if self.escalation_level != old_level:
                level_name = ESCALATION_NAMES.get(self.escalation_level, "UNKNOWN")
                logger.warning(
                    "ESCALATION cell=%s level=%d(%s) ip=%s interactions=%d",
                    self.cell_id, self.escalation_level, level_name,
                    source_ip, self.interaction_count,
                )
                emit_security_event(
                    cell_id=self.cell_id,
                    event_type="honeypot_escalation",
                    severity="high" if self.escalation_level >= 3 else "medium",
                    details=json.dumps({
                        "cell_id": self.cell_id,
                        "new_level": self.escalation_level,
                        "level_name": level_name,
                        "source_ip": source_ip,
                        "tools_seen": sorted(self.tools_seen),
                        "interaction_count": self.interaction_count,
                        "injection_attempts": self.injection_attempts,
                    }),
                )

            # Lock at level 3+ and activate shun engine
            if self.escalation_level >= 3 and not self.locked:
                self.locked = True
                self.status = "locked"
                logger.warning(
                    "CELL LOCKED cell=%s ip=%s - attacker committed, full capture active",
                    self.cell_id, source_ip,
                )
                # Trigger auto-shun: firewall blocks this IP
                auto_shun_from_cell(
                    cell_id=self.cell_id,
                    source_ip=source_ip,
                    escalation_level=self.escalation_level,
                )

            if self.escalation_level >= 5:
                self.status = "burning"

            # Analyze timing patterns
            timing = {}
            if len(self.request_timestamps) >= 3:
                timing = analyze_request_timing(self.request_timestamps[-20:])

            # Build tool report
            tool_report = build_tool_report(tool_sig, headers, path, body)

            return {
                "cell_id": self.cell_id,
                "escalation_level": self.escalation_level,
                "escalation_name": ESCALATION_NAMES.get(self.escalation_level, "UNKNOWN"),
                "interaction_count": self.interaction_count,
                "locked": self.locked,
                "evidence_type": evidence_type,
                "tool_signature": tool_sig,
                "injection_detected": injection,
                "timing_analysis": timing,
                "tool_report": tool_report,
            }

    def _classify_interaction(
        self, method: str, path: str, tool_sig: str, injection: Optional[str]
    ) -> str:
        """Classify the type of interaction for evidence tagging."""
        if injection:
            return "injection_attempt"

        path_lower = path.lower()

        if any(p in path_lower for p in ["/admin", "/administrator", "/manager", "/console"]):
            return "admin_probe"
        if any(p in path_lower for p in ["/.env", "/.git", "/config", "/secret", "/private"]):
            return "sensitive_file_probe"
        if any(p in path_lower for p in ["/api/keys", "/api/tokens", "/credentials"]):
            return "credential_harvest"
        if any(p in path_lower for p in ["/backup", "/dump", "/export", "/database"]):
            return "data_exfil_attempt"
        if any(p in path_lower for p in ["/users", "/accounts", "/members"]):
            return "user_enumeration"
        if any(p in path_lower for p in ["/network", "/internal", "/infrastructure"]):
            return "recon_internal"
        if any(p in path_lower for p in ["/status", "/health", "/info", "/version"]):
            return "service_discovery"
        if method in ("POST", "PUT", "PATCH", "DELETE"):
            return "mutation_attempt"

        return "general_probe"

    def _evaluate_escalation(self, threshold: int) -> None:
        """Evaluate whether to escalate the threat level."""
        # Level 1: Multiple interactions
        if self.interaction_count >= threshold and self.escalation_level < 1:
            self.escalation_level = 1

        # Level 2: Active probing (multiple paths or tools)
        unique_paths = len(set(self.paths_visited))
        if (unique_paths >= 3 or len(self.tools_seen) > 1) and self.escalation_level < 2:
            self.escalation_level = 2

        # Level 3: Injection attempts or heavy probing
        if (self.injection_attempts > 0 or unique_paths >= 6) and self.escalation_level < 3:
            self.escalation_level = 3

        # Level 4: Sustained engagement
        if self.interaction_count >= threshold * 5 and self.escalation_level < 4:
            self.escalation_level = 4

        # Level 5: Extensive - they're fully committed
        if self.interaction_count >= threshold * 10 and self.escalation_level < 5:
            self.escalation_level = 5

    def persist(self) -> None:
        """Persist cell state to database."""
        record = MirrorCellRecord.query.filter_by(cell_id=self.cell_id).first()
        now = datetime.now(UTC)

        if not record:
            record = MirrorCellRecord(
                cell_id=self.cell_id,
                attacker_fingerprint=self.attacker_fingerprint,
                source_ip=self.source_ip,
                first_seen=now,
                last_seen=now,
                escalation_level=self.escalation_level,
                total_interactions=self.interaction_count,
                locked=self.locked,
                status=self.status,
            )
            db.session.add(record)
        else:
            record.last_seen = now
            record.escalation_level = self.escalation_level
            record.total_interactions = self.interaction_count
            record.locked = self.locked
            record.status = self.status

        db.session.commit()

    def to_dict(self) -> dict:
        """Export cell state as dictionary."""
        return {
            "cell_id": self.cell_id,
            "attacker_fingerprint": self.attacker_fingerprint,
            "source_ip": self.source_ip,
            "escalation_level": self.escalation_level,
            "escalation_name": ESCALATION_NAMES.get(self.escalation_level, "UNKNOWN"),
            "interaction_count": self.interaction_count,
            "locked": self.locked,
            "status": self.status,
            "tools_seen": sorted(self.tools_seen),
            "unique_paths": len(set(self.paths_visited)),
            "injection_attempts": self.injection_attempts,
        }


class CellManager:
    """Manages the lifecycle of all active mirror cells.

    Thread-safe. Cells are created on first contact and persist
    for the lifetime of the application (or until explicitly purged).
    """

    def __init__(self):
        self._cells: dict[str, MirrorCell] = {}
        self._lock = threading.Lock()

    def get_or_create_cell(
        self,
        source_ip: str,
        headers: dict,
    ) -> MirrorCell:
        """Get an existing cell or create a new one for this attacker."""
        user_agent = headers.get("User-Agent", headers.get("user-agent", ""))
        accept_lang = headers.get("Accept-Language", headers.get("accept-language", ""))
        accept_enc = headers.get("Accept-Encoding", headers.get("accept-encoding", ""))

        fingerprint = compute_attacker_fingerprint(source_ip, user_agent, accept_lang, accept_enc)

        with self._lock:
            # Check if we already have a cell for this fingerprint
            for cell in self._cells.values():
                if cell.attacker_fingerprint == fingerprint:
                    return cell

            # Create new cell
            cell_id = hashlib.sha256(
                f"{fingerprint}:{time.time()}".encode()
            ).hexdigest()[:16]

            cell = MirrorCell(
                cell_id=cell_id,
                attacker_fingerprint=fingerprint,
                source_ip=source_ip,
            )
            self._cells[cell_id] = cell

            logger.info(
                "NEW CELL cell=%s ip=%s fingerprint=%s",
                cell_id, source_ip, fingerprint[:16],
            )

            emit_security_event(
                cell_id=cell_id,
                event_type="honeypot_cell_created",
                severity="medium",
                details=json.dumps({
                    "cell_id": cell_id,
                    "source_ip": source_ip,
                    "fingerprint": fingerprint,
                    "user_agent": user_agent,
                }),
            )

            return cell

    def get_cell(self, cell_id: str) -> Optional[MirrorCell]:
        """Get a cell by ID."""
        return self._cells.get(cell_id)

    def get_all_cells(self) -> list[dict]:
        """Get summary of all active cells."""
        with self._lock:
            return [cell.to_dict() for cell in self._cells.values()]

    def get_locked_cells(self) -> list[dict]:
        """Get only locked (committed attacker) cells."""
        with self._lock:
            return [cell.to_dict() for cell in self._cells.values() if cell.locked]

    def cell_count(self) -> int:
        """Number of active cells."""
        return len(self._cells)


# Global cell manager instance
cell_manager = CellManager()
