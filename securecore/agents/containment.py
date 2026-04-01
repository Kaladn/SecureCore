"""Containment Advisor Agent - recommends and triggers containment actions.

The containment advisor watches escalation agent decisions and
determines when to activate containment measures:

  - Auto-shun via Windows Firewall
  - Socket kill recommendations
  - Cell lock confirmation
  - Evidence preservation triggers

The containment advisor is the bridge between agent interpretation
and the control plane (shun engine). It provides the authorization
signal that the control plane acts on.

Hard rule: the containment advisor RECOMMENDS. The control plane
EXECUTES. This separation ensures the audit trail shows both
the recommendation and the execution.
"""

import time
from typing import Optional

from securecore.agents.base import Agent, AgentDecision
from securecore.substrates.base import Substrate, SubstrateRecord


class ContainmentAdvisorAgent(Agent):
    """Recommends containment actions based on escalation decisions."""

    name = "containment"

    def __init__(self, decision_substrate: Substrate):
        super().__init__(decision_substrate)
        self._shun_recommended: set[str] = set()  # cell_ids where shun was recommended
        self._lock_recommended: set[str] = set()
        self._cells_source_ips: dict[str, str] = {}

    def consume(self, record: SubstrateRecord) -> None:
        # Track cell -> IP mapping from mirror substrate
        if record.substrate == "mirror" and record.cell_id:
            ip = record.payload.get("source_ip", "")
            if ip:
                self._cells_source_ips[record.cell_id] = ip

        # Process escalation agent decisions
        if record.substrate != "agent_decisions":
            return

        p = record.payload
        if p.get("agent_name") != "escalation":
            return
        if p.get("decision_type") != "escalation_recommendation":
            return

        cell_id = record.cell_id
        if not cell_id:
            return

        ctx = p.get("context", {})
        new_level = ctx.get("new_level", 0)
        action = p.get("recommended_action", "")
        source_ip = self._cells_source_ips.get(cell_id, "unknown")

        # Level 3+: recommend cell lock
        if new_level >= 3 and cell_id not in self._lock_recommended:
            self._lock_recommended.add(cell_id)
            self.emit(AgentDecision(
                agent_name=self.name,
                decision_type="lock_cell",
                confidence=0.95,
                cell_id=cell_id,
                reasoning=(
                    f"Escalation level {new_level} reached. "
                    f"Cell should be permanently locked. "
                    f"Source IP: {source_ip}"
                ),
                recommended_action="lock_cell",
                context={
                    "source_ip": source_ip,
                    "escalation_level": new_level,
                    "signals": ctx.get("signals", {}),
                },
            ))

        # Level 3+: recommend shun
        if new_level >= 3 and cell_id not in self._shun_recommended:
            self._shun_recommended.add(cell_id)
            self.emit(AgentDecision(
                agent_name=self.name,
                decision_type="shun_ip",
                confidence=0.9,
                cell_id=cell_id,
                reasoning=(
                    f"Escalation level {new_level}: recommending firewall block "
                    f"for {source_ip}. Signals: injection={ctx.get('signals', {}).get('injection', False)}, "
                    f"scanner={ctx.get('signals', {}).get('scanner', False)}, "
                    f"sustained={ctx.get('signals', {}).get('sustained_probing', False)}"
                ),
                recommended_action="shun_ip",
                context={
                    "ip": source_ip,
                    "cell_id": cell_id,
                    "escalation_level": new_level,
                },
            ))

        # Level 5: recommend evidence preservation
        if new_level >= 5:
            self.emit(AgentDecision(
                agent_name=self.name,
                decision_type="preserve_evidence",
                confidence=1.0,
                cell_id=cell_id,
                reasoning=(
                    f"Level 5 (BURNING): evidence package should be exported "
                    f"and preserved for {source_ip}"
                ),
                recommended_action="export_evidence_bundle",
                context={
                    "source_ip": source_ip,
                    "cell_id": cell_id,
                    "escalation_level": new_level,
                },
            ))

    def get_containment_status(self) -> dict:
        return {
            "cells_shun_recommended": sorted(self._shun_recommended),
            "cells_lock_recommended": sorted(self._lock_recommended),
            "total_shun_recommendations": len(self._shun_recommended),
            "total_lock_recommendations": len(self._lock_recommended),
        }
