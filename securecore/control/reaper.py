"""Reaper - autonomous containment executor.

The Reaper is a standalone stack component. It does NOT require Flask.
It watches the agent_decisions substrate for containment recommendations
and executes them. It is the organism's immune response.

The Reaper:
  - Subscribes to agent_decisions substrate
  - Filters for containment agent decisions (shun_ip, lock_cell, preserve_evidence)
  - Validates against policy (thresholds, cooldowns, protected IPs)
  - Executes via the shun engine (firewall rules, socket kills)
  - Records every action in the operator substrate
  - Emits confirmation back to agent_decisions

The Reaper can run:
  1. Embedded in the Flask app (started by app factory)
  2. Standalone as a background daemon (python -m securecore.control.reaper)
  3. One-shot replay mode (process historical substrate records)

Hard rules:
  - Reaper NEVER reads raw evidence. It reads agent decisions only.
  - Reaper NEVER modifies substrates other than operator.
  - Reaper actions are always logged before execution.
  - Reaper respects cooldowns (won't re-shun the same IP within window).
  - Reaper respects protected IPs unconditionally.
  - Reaper can be paused without losing state.
"""

import json
import logging
import threading
import time
from typing import Optional

from securecore.substrates.base import Substrate, SubstrateRecord
from securecore.substrates.agent_decisions import AgentDecisionsSubstrate
from securecore.substrates.operator import OperatorSubstrate
from securecore.control.shun import (
    shun_ip, unshun_ip, is_shunned, PROTECTED_IPS,
)

logger = logging.getLogger("control.reaper")


class ReaperPolicy:
    """Policy governing what the Reaper will and won't do."""

    def __init__(
        self,
        min_confidence: float = 0.7,
        shun_cooldown_seconds: float = 300.0,
        auto_shun_enabled: bool = True,
        auto_lock_enabled: bool = True,
        auto_preserve_enabled: bool = True,
        dry_run: bool = False,
    ):
        self.min_confidence = min_confidence
        self.shun_cooldown_seconds = shun_cooldown_seconds
        self.auto_shun_enabled = auto_shun_enabled
        self.auto_lock_enabled = auto_lock_enabled
        self.auto_preserve_enabled = auto_preserve_enabled
        self.dry_run = dry_run

    def to_dict(self) -> dict:
        return {
            "min_confidence": self.min_confidence,
            "shun_cooldown_seconds": self.shun_cooldown_seconds,
            "auto_shun_enabled": self.auto_shun_enabled,
            "auto_lock_enabled": self.auto_lock_enabled,
            "auto_preserve_enabled": self.auto_preserve_enabled,
            "dry_run": self.dry_run,
        }


class Reaper:
    """Autonomous containment executor.

    Watches agent_decisions, validates against policy, executes containment.
    """

    def __init__(
        self,
        decisions_substrate: AgentDecisionsSubstrate,
        operator_substrate: OperatorSubstrate,
        policy: Optional[ReaperPolicy] = None,
    ):
        self._decisions_sub = decisions_substrate
        self._operator_sub = operator_substrate
        self._policy = policy or ReaperPolicy()
        self._lock = threading.Lock()
        self._running = False
        self._paused = False

        # Tracking
        self._shun_timestamps: dict[str, float] = {}  # ip -> last shun time
        self._actions_taken: int = 0
        self._actions_skipped: int = 0
        self._cells_locked: set[str] = set()
        self._ips_shunned: set[str] = set()

    def start(self) -> None:
        """Start the Reaper. Subscribe to decisions substrate."""
        self._running = True
        self._decisions_sub.subscribe(self._on_decision)
        logger.warning("REAPER ONLINE - policy: %s", json.dumps(self._policy.to_dict()))

        self._operator_sub.record_action(
            action="reaper_start",
            target="system",
            operator="reaper",
            details=json.dumps(self._policy.to_dict()),
        )

    def stop(self) -> None:
        """Stop the Reaper."""
        self._running = False
        self._decisions_sub.unsubscribe(self._on_decision)
        logger.warning(
            "REAPER OFFLINE - actions=%d skipped=%d shunned=%d locked=%d",
            self._actions_taken, self._actions_skipped,
            len(self._ips_shunned), len(self._cells_locked),
        )

        self._operator_sub.record_action(
            action="reaper_stop",
            target="system",
            operator="reaper",
            details=json.dumps(self.stats),
        )

    def pause(self) -> None:
        """Pause execution. Reaper still receives decisions but won't act."""
        self._paused = True
        logger.warning("REAPER PAUSED")
        self._operator_sub.record_action(
            action="reaper_pause", target="system", operator="reaper",
        )

    def resume(self) -> None:
        """Resume execution."""
        self._paused = False
        logger.warning("REAPER RESUMED")
        self._operator_sub.record_action(
            action="reaper_resume", target="system", operator="reaper",
        )

    def _on_decision(self, record: SubstrateRecord) -> None:
        """Callback from agent_decisions substrate."""
        if not self._running or self._paused:
            return

        if record.substrate != "agent_decisions":
            return

        payload = record.payload
        agent_name = payload.get("agent_name", "")
        decision_type = payload.get("decision_type", "")

        # Only act on containment agent decisions
        if agent_name != "containment":
            return

        confidence = payload.get("confidence", 0.0)
        if confidence < self._policy.min_confidence:
            self._actions_skipped += 1
            logger.info(
                "REAPER SKIP: confidence %.2f < threshold %.2f for %s",
                confidence, self._policy.min_confidence, decision_type,
            )
            return

        cell_id = record.cell_id
        context = payload.get("context", {})

        if decision_type == "shun_ip":
            self._execute_shun(cell_id, context, confidence)
        elif decision_type == "lock_cell":
            self._execute_lock(cell_id, context, confidence)
        elif decision_type == "preserve_evidence":
            self._execute_preserve(cell_id, context, confidence)

    def _execute_shun(self, cell_id: str, context: dict, confidence: float) -> None:
        """Execute an IP shun."""
        if not self._policy.auto_shun_enabled:
            self._actions_skipped += 1
            return

        ip = context.get("ip", "")
        if not ip or ip in PROTECTED_IPS:
            self._actions_skipped += 1
            return

        # Cooldown check
        last_shun = self._shun_timestamps.get(ip, 0)
        if time.time() - last_shun < self._policy.shun_cooldown_seconds:
            return  # still in cooldown, silent skip

        if is_shunned(ip):
            return  # already shunned

        with self._lock:
            # Log BEFORE execution
            self._operator_sub.record_action(
                action="reaper_shun_execute",
                target=ip,
                operator="reaper",
                cell_id=cell_id,
                details=json.dumps({
                    "confidence": confidence,
                    "escalation_level": context.get("escalation_level", 0),
                    "dry_run": self._policy.dry_run,
                }),
            )

            # Execute
            result = shun_ip(
                ip=ip,
                reason=f"Reaper auto-shun: cell={cell_id} confidence={confidence:.2f}",
                cell_id=cell_id,
                escalation_level=context.get("escalation_level", 0),
                operator_substrate=self._operator_sub,
                dry_run=self._policy.dry_run,
            )

            if result.get("ok"):
                self._shun_timestamps[ip] = time.time()
                self._ips_shunned.add(ip)
                self._actions_taken += 1

                logger.warning(
                    "REAPER SHUN: %s cell=%s confidence=%.2f fw=%s",
                    ip, cell_id, confidence, result.get("firewall_rule_created"),
                )

    def _execute_lock(self, cell_id: str, context: dict, confidence: float) -> None:
        """Execute a cell lock."""
        if not self._policy.auto_lock_enabled:
            self._actions_skipped += 1
            return

        if cell_id in self._cells_locked:
            return  # already locked

        with self._lock:
            self._operator_sub.record_action(
                action="reaper_lock_execute",
                target=cell_id,
                operator="reaper",
                cell_id=cell_id,
                details=json.dumps({
                    "confidence": confidence,
                    "source_ip": context.get("source_ip", ""),
                    "escalation_level": context.get("escalation_level", 0),
                }),
            )

            self._cells_locked.add(cell_id)
            self._actions_taken += 1

            logger.warning(
                "REAPER LOCK: cell=%s ip=%s confidence=%.2f",
                cell_id, context.get("source_ip", ""), confidence,
            )

    def _execute_preserve(self, cell_id: str, context: dict, confidence: float) -> None:
        """Execute evidence preservation."""
        if not self._policy.auto_preserve_enabled:
            self._actions_skipped += 1
            return

        with self._lock:
            self._operator_sub.record_action(
                action="reaper_preserve_execute",
                target=cell_id,
                operator="reaper",
                cell_id=cell_id,
                details=json.dumps({
                    "confidence": confidence,
                    "source_ip": context.get("source_ip", ""),
                    "recommendation": "export_evidence_bundle",
                }),
            )

            self._actions_taken += 1

            logger.warning(
                "REAPER PRESERVE: cell=%s - evidence bundle flagged for export",
                cell_id,
            )

    def replay(self, since_sequence: int = 0) -> dict:
        """Replay historical decisions through the Reaper.

        Useful for testing policy changes against real data.
        """
        processed = 0
        for record in self._decisions_sub.stream(since_sequence=since_sequence):
            self._on_decision(record)
            processed += 1

        return {
            "processed": processed,
            "actions_taken": self._actions_taken,
            "actions_skipped": self._actions_skipped,
        }

    @property
    def stats(self) -> dict:
        return {
            "running": self._running,
            "paused": self._paused,
            "actions_taken": self._actions_taken,
            "actions_skipped": self._actions_skipped,
            "ips_shunned": sorted(self._ips_shunned),
            "cells_locked": sorted(self._cells_locked),
            "policy": self._policy.to_dict(),
        }

    @property
    def is_alive(self) -> bool:
        return self._running and not self._paused
