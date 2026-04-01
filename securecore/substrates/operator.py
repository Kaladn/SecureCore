"""Operator Substrate - records what the operator did.

Every operator action gets recorded here:
  - manual shuns and unshuns
  - configuration changes
  - cell inspections
  - evidence exports
  - system commands
  - acknowledgments

This substrate is the audit trail for human actions.
When something goes wrong, this answers "who did what?"
"""

from typing import Optional

from securecore.substrates.base import Substrate


class OperatorSubstrate(Substrate):
    """Operator action records substrate."""

    name = "operator"

    def validate_payload(self, record_type: str, payload: dict) -> None:
        if "action" not in payload:
            raise ValueError("operator records require an action field")

    def record_action(
        self,
        action: str,
        target: str,
        operator: str = "system",
        details: str = "",
        cell_id: str = "",
        metadata: Optional[dict] = None,
    ) -> "SubstrateRecord":
        """Record an operator action."""
        payload = {
            "action": action,
            "target": target,
            "operator": operator,
            "details": details,
            "metadata": metadata or {},
        }
        return self.append(
            record_type=f"operator:{action}",
            payload=payload,
            cell_id=cell_id,
        )

    def record_shun(
        self,
        ip: str,
        reason: str,
        operator: str = "system",
        cell_id: str = "",
        firewall_rule: bool = False,
    ) -> "SubstrateRecord":
        return self.record_action(
            action="shun",
            target=ip,
            operator=operator,
            details=reason,
            cell_id=cell_id,
            metadata={"firewall_rule_created": firewall_rule},
        )

    def record_unshun(
        self,
        ip: str,
        reason: str,
        operator: str = "admin",
        cell_id: str = "",
    ) -> "SubstrateRecord":
        return self.record_action(
            action="unshun",
            target=ip,
            operator=operator,
            details=reason,
            cell_id=cell_id,
        )

    def record_inspection(
        self,
        target: str,
        operator: str = "admin",
        cell_id: str = "",
    ) -> "SubstrateRecord":
        return self.record_action(
            action="inspect",
            target=target,
            operator=operator,
            cell_id=cell_id,
        )

    def record_export(
        self,
        cell_id: str,
        export_path: str,
        operator: str = "admin",
    ) -> "SubstrateRecord":
        return self.record_action(
            action="evidence_export",
            target=export_path,
            operator=operator,
            cell_id=cell_id,
        )

    def get_operator_history(self, operator: str = "", limit: int = 200) -> list[dict]:
        """Get operator action history."""
        results = []
        for record in self.stream():
            if operator and record.payload.get("operator") != operator:
                continue
            results.append(record.to_dict())
            if len(results) >= limit:
                break
        return results
