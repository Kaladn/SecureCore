"""Agent Decisions Substrate - records what agents decided and why.

This is NOT primary truth. This is interpretation. Agents read from
other substrates (ingress, mirror, evidence) and emit their analysis
here. The decisions substrate exists so that:

  1. Every agent decision is auditable
  2. Agent reasoning can be reviewed after the fact
  3. The control plane can act on recommendations
  4. Decisions can be correlated with outcomes
  5. Agent behavior can be tuned based on historical accuracy
"""

from typing import Optional

from securecore.substrates.base import Substrate


class AgentDecisionsSubstrate(Substrate):
    """Agent decision records substrate."""

    name = "agent_decisions"

    def validate_payload(self, record_type: str, payload: dict) -> None:
        if "agent_decision:" in record_type:
            if "agent_name" not in payload:
                raise ValueError("agent decision requires agent_name")
            if "confidence" not in payload:
                raise ValueError("agent decision requires confidence")

    def record_decision(
        self,
        agent_name: str,
        decision_type: str,
        confidence: float,
        cell_id: str = "",
        reasoning: str = "",
        recommended_action: str = "",
        context: Optional[dict] = None,
    ) -> "SubstrateRecord":
        """Record an agent's decision."""
        payload = {
            "agent_name": agent_name,
            "decision_type": decision_type,
            "confidence": min(1.0, max(0.0, confidence)),
            "reasoning": reasoning,
            "recommended_action": recommended_action,
            "context": context or {},
        }
        return self.append(
            record_type=f"agent_decision:{decision_type}",
            payload=payload,
            cell_id=cell_id,
        )

    def get_decisions_by_agent(self, agent_name: str, limit: int = 200) -> list[dict]:
        """Get all decisions from a specific agent."""
        results = []
        for record in self.stream():
            if record.payload.get("agent_name") == agent_name:
                results.append(record.to_dict())
                if len(results) >= limit:
                    break
        return results

    def get_decisions_for_cell(self, cell_id: str, limit: int = 200) -> list[dict]:
        """Get all agent decisions related to a cell."""
        records = self.query(cell_id=cell_id, limit=limit)
        return [r.to_dict() for r in records]

    def get_action_recommendations(self, action: str, limit: int = 50) -> list[dict]:
        """Get all decisions that recommended a specific action."""
        results = []
        for record in self.stream():
            if record.payload.get("recommended_action") == action:
                results.append(record.to_dict())
                if len(results) >= limit:
                    break
        return results
