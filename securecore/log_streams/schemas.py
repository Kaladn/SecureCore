"""Logging schemas - one schema per concern.

Every log stream has its own schema. No mixed logs. Everything is
timestamped, sequenced, and cell-linked where applicable.

Log streams:
  1. raw_ingress    - every raw request as it arrived
  2. normalized     - cleaned, typed, classified events
  3. forensic       - evidence-grade records with chain hashes
  4. agent_decision - what agents decided and why
  5. operator       - what the operator did
  6. health         - system health and performance
  7. chain_anchor   - periodic chain state snapshots for fast verification
"""

from datetime import datetime, UTC


def _now() -> str:
    return datetime.now(UTC).isoformat()


def raw_ingress_entry(
    source_ip: str,
    source_port: int | None,
    method: str,
    path: str,
    headers: dict,
    body_size: int,
    body_hash: str,
    protocol: str = "HTTP/1.1",
    tls_version: str = "",
    cell_id: str = "",
) -> dict:
    """Schema for raw ingress log entries."""
    return {
        "stream": "raw_ingress",
        "timestamp": _now(),
        "source_ip": source_ip,
        "source_port": source_port,
        "method": method,
        "path": path,
        "header_count": len(headers),
        "headers": headers,
        "body_size": body_size,
        "body_hash": body_hash,
        "protocol": protocol,
        "tls_version": tls_version,
        "cell_id": cell_id,
    }


def normalized_event_entry(
    event_type: str,
    severity: str,
    source: str,
    cell_id: str = "",
    details: str = "",
    tags: list[str] | None = None,
) -> dict:
    """Schema for normalized event log entries."""
    return {
        "stream": "normalized",
        "timestamp": _now(),
        "event_type": event_type,
        "severity": severity,
        "source": source,
        "cell_id": cell_id,
        "details": details,
        "tags": tags or [],
    }


def forensic_entry(
    cell_id: str,
    evidence_type: str,
    method: str,
    path: str,
    source_ip: str,
    tool_signature: str,
    chain_hash: str,
    sequence: int,
) -> dict:
    """Schema for forensic evidence log entries."""
    return {
        "stream": "forensic",
        "timestamp": _now(),
        "cell_id": cell_id,
        "evidence_type": evidence_type,
        "method": method,
        "path": path,
        "source_ip": source_ip,
        "tool_signature": tool_signature,
        "chain_hash": chain_hash,
        "sequence": sequence,
    }


def agent_decision_entry(
    agent_name: str,
    decision_type: str,
    confidence: float,
    cell_id: str = "",
    recommended_action: str = "",
    reasoning: str = "",
) -> dict:
    """Schema for agent decision log entries."""
    return {
        "stream": "agent_decision",
        "timestamp": _now(),
        "agent_name": agent_name,
        "decision_type": decision_type,
        "confidence": confidence,
        "cell_id": cell_id,
        "recommended_action": recommended_action,
        "reasoning": reasoning,
    }


def operator_action_entry(
    action: str,
    target: str,
    operator: str = "system",
    details: str = "",
    cell_id: str = "",
) -> dict:
    """Schema for operator action log entries."""
    return {
        "stream": "operator",
        "timestamp": _now(),
        "action": action,
        "target": target,
        "operator": operator,
        "details": details,
        "cell_id": cell_id,
    }


def health_entry(
    component: str,
    status: str,
    metric_name: str = "",
    metric_value: float = 0.0,
    details: str = "",
) -> dict:
    """Schema for health/performance log entries."""
    return {
        "stream": "health",
        "timestamp": _now(),
        "component": component,
        "status": status,
        "metric_name": metric_name,
        "metric_value": metric_value,
        "details": details,
    }


def chain_anchor_entry(
    substrate: str,
    sequence: int,
    chain_hash: str,
    record_count: int,
    verification_result: str = "intact",
) -> dict:
    """Schema for chain anchor snapshots."""
    return {
        "stream": "chain_anchor",
        "timestamp": _now(),
        "substrate": substrate,
        "sequence": sequence,
        "chain_hash": chain_hash,
        "record_count": record_count,
        "verification_result": verification_result,
    }


def llm_audit_entry(
    query_id: str,
    role: str,
    caller_id: str,
    model: str,
    model_digest: str = "",
    system_prompt_hash: str = "",
    sequence: int = 0,
    prompt_hash: str = "",
    context_bundle_hash: str = "",
    source_labels: list[str] | None = None,
    response_hash: str = "",
    prompt_len: int = 0,
    response_len: int = 0,
    success: bool = False,
) -> dict:
    """Schema for LLM invocation audit entries."""
    return {
        "stream": "llm_audit",
        "timestamp": _now(),
        "query_id": query_id,
        "role": role,
        "caller_id": caller_id,
        "model": model,
        "model_digest": model_digest,
        "system_prompt_hash": system_prompt_hash,
        "sequence": sequence,
        "prompt_hash": prompt_hash,
        "context_bundle_hash": context_bundle_hash,
        "source_labels": source_labels or [],
        "response_hash": response_hash,
        "prompt_len": prompt_len,
        "response_len": response_len,
        "success": success,
    }
