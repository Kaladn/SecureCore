"""Mirror Substrate - per-cell lifecycle truth.

Records every state change in a mirror cell's life. This is NOT the
same as the evidence substrate - this tracks the CELL itself:
  - creation
  - fingerprint assignment
  - escalation transitions
  - lock events
  - decoy state selections
  - shun triggers
  - cell death/expiry

The mirror substrate answers: "What happened to this cell and when?"
The evidence substrate answers: "What did the attacker do?"
"""

from typing import Optional

from securecore.substrates.base import Substrate


class MirrorSubstrate(Substrate):
    """Mirror cell lifecycle substrate."""

    name = "mirror"

    def validate_payload(self, record_type: str, payload: dict) -> None:
        if record_type == "cell_created" and "attacker_fingerprint" not in payload:
            raise ValueError("cell_created requires attacker_fingerprint")
        if record_type == "escalation" and "new_level" not in payload:
            raise ValueError("escalation requires new_level")

    def record_cell_created(
        self,
        cell_id: str,
        attacker_fingerprint: str,
        source_ip: str,
        user_agent: str,
        trigger_path: str,
    ) -> "SubstrateRecord":
        """Record the birth of a mirror cell."""
        return self.append(
            record_type="cell_created",
            payload={
                "attacker_fingerprint": attacker_fingerprint,
                "source_ip": source_ip,
                "user_agent": user_agent,
                "trigger_path": trigger_path,
            },
            cell_id=cell_id,
        )

    def record_escalation(
        self,
        cell_id: str,
        old_level: int,
        new_level: int,
        level_name: str,
        trigger_reason: str,
        interaction_count: int,
        tools_seen: list[str],
        injection_attempts: int,
    ) -> "SubstrateRecord":
        """Record an escalation transition."""
        return self.append(
            record_type="escalation",
            payload={
                "old_level": old_level,
                "new_level": new_level,
                "level_name": level_name,
                "trigger_reason": trigger_reason,
                "interaction_count": interaction_count,
                "tools_seen": tools_seen,
                "injection_attempts": injection_attempts,
            },
            cell_id=cell_id,
        )

    def record_cell_locked(
        self,
        cell_id: str,
        source_ip: str,
        escalation_level: int,
        interaction_count: int,
    ) -> "SubstrateRecord":
        """Record the permanent lock of a cell."""
        return self.append(
            record_type="cell_locked",
            payload={
                "source_ip": source_ip,
                "escalation_level": escalation_level,
                "interaction_count": interaction_count,
            },
            cell_id=cell_id,
        )

    def record_decoy_served(
        self,
        cell_id: str,
        decoy_type: str,
        path: str,
        response_hash: str,
    ) -> "SubstrateRecord":
        """Record which decoy was served to an attacker."""
        return self.append(
            record_type="decoy_served",
            payload={
                "decoy_type": decoy_type,
                "path": path,
                "response_hash": response_hash,
            },
            cell_id=cell_id,
        )

    def record_shun_triggered(
        self,
        cell_id: str,
        source_ip: str,
        escalation_level: int,
        firewall_rule_created: bool,
    ) -> "SubstrateRecord":
        """Record that a shun was triggered from this cell."""
        return self.append(
            record_type="shun_triggered",
            payload={
                "source_ip": source_ip,
                "escalation_level": escalation_level,
                "firewall_rule_created": firewall_rule_created,
            },
            cell_id=cell_id,
        )

    def record_cell_interaction(
        self,
        cell_id: str,
        interaction_count: int,
        escalation_level: int,
        path: str,
        tool_signature: str,
    ) -> "SubstrateRecord":
        """Record a cell interaction tick (lightweight, every request)."""
        return self.append(
            record_type="interaction",
            payload={
                "interaction_count": interaction_count,
                "escalation_level": escalation_level,
                "path": path,
                "tool_signature": tool_signature,
            },
            cell_id=cell_id,
        )
