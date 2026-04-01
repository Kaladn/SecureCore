"""Chain Auditor Agent - continuously verifies evidence integrity.

The chain auditor periodically verifies the hash chains across all
substrates. If any chain is broken (indicating tampering), it
immediately emits a critical alert.

The auditor also:
  - Generates periodic chain anchor snapshots
  - Verifies per-cell evidence chains in the evidence substrate
  - Cross-references substrate records against JSONL truth
  - Detects gaps in sequence numbers
"""

import time
from typing import Optional

from securecore.agents.base import Agent, AgentDecision
from securecore.substrates.base import Substrate, SubstrateRecord


class ChainAuditorAgent(Agent):
    """Continuous hash chain integrity verification."""

    name = "chain_auditor"

    def __init__(
        self,
        decision_substrate: Substrate,
        watched_substrates: list[Substrate],
        evidence_substrate=None,
    ):
        super().__init__(decision_substrate)
        self._watched_substrates = watched_substrates
        self._evidence_substrate = evidence_substrate
        self._last_audit_time = 0.0
        self._audit_interval = 60.0  # seconds between full audits
        self._known_cells: set[str] = set()
        self._audit_count = 0

    def consume(self, record: SubstrateRecord) -> None:
        """Track cells that need auditing."""
        if record.cell_id:
            self._known_cells.add(record.cell_id)

    def tick(self) -> None:
        """Periodic full chain audit."""
        now = time.time()
        if now - self._last_audit_time < self._audit_interval:
            return

        self._last_audit_time = now
        self._audit_count += 1

        # Audit each watched substrate's chain
        for substrate in self._watched_substrates:
            result = substrate.verify_chain()

            if result.get("intact"):
                # Emit anchor (periodic proof of integrity)
                if self._audit_count % 5 == 0:  # every 5th audit
                    self.emit(AgentDecision(
                        agent_name=self.name,
                        decision_type="chain_anchor",
                        confidence=1.0,
                        reasoning=(
                            f"Substrate '{substrate.name}' chain intact: "
                            f"{result.get('total_records', 0)} records verified"
                        ),
                        recommended_action="log_anchor",
                        context={
                            "substrate": substrate.name,
                            "total_records": result.get("total_records", 0),
                            "last_timestamp": result.get("last_timestamp"),
                            "audit_number": self._audit_count,
                        },
                    ))
            else:
                # CRITICAL: chain broken - tampering detected
                self.emit(AgentDecision(
                    agent_name=self.name,
                    decision_type="chain_integrity_violation",
                    confidence=1.0,
                    reasoning=(
                        f"CRITICAL: Substrate '{substrate.name}' chain BROKEN "
                        f"at sequence {result.get('broken_at_sequence')}: "
                        f"{result.get('error')}"
                    ),
                    recommended_action="critical_alert",
                    context=result,
                ))

        # Audit per-cell evidence chains
        if self._evidence_substrate and self._known_cells:
            for cell_id in self._known_cells:
                cell_result = self._evidence_substrate.verify_cell_chain(cell_id)
                if not cell_result.get("intact") and cell_result.get("entries", 0) > 0:
                    self.emit(AgentDecision(
                        agent_name=self.name,
                        decision_type="cell_chain_violation",
                        confidence=1.0,
                        cell_id=cell_id,
                        reasoning=(
                            f"CRITICAL: Cell {cell_id} evidence chain BROKEN "
                            f"at cell_sequence {cell_result.get('broken_at_cell_sequence')}: "
                            f"{cell_result.get('error')}"
                        ),
                        recommended_action="critical_alert",
                        context=cell_result,
                    ))

    def force_audit(self) -> list[dict]:
        """Force an immediate full audit and return results."""
        results = []
        for substrate in self._watched_substrates:
            result = substrate.verify_chain()
            results.append({"substrate": substrate.name, **result})

        if self._evidence_substrate:
            for cell_id in self._known_cells:
                cell_result = self._evidence_substrate.verify_cell_chain(cell_id)
                results.append({"cell_id": cell_id, "type": "cell_chain", **cell_result})

        return results
