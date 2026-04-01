"""Cognitive Agent - multi-anchor authenticity and threat assessment.

This is a pure-Python adaptation of the useful parts of the larger cognitive
engine concept: multiple anchor scores, cross-anchor consensus, and a
structured output that downstream control logic can reason about.

It does not replace the profiler. It complements it.
"""

from __future__ import annotations

import statistics
import time
from dataclasses import dataclass, field

from securecore.agents.base import Agent, AgentDecision
from securecore.core.fingerprint import detect_injection_attempt
from securecore.substrates.base import Substrate, SubstrateRecord

TEMPORAL_ANCHORS = [
    "temporal_rhythm",
    "temporal_cadence",
    "temporal_sequence",
    "temporal_duration",
]
BEHAVIORAL_ANCHORS = [
    "behavioral_intent",
    "behavioral_pattern",
    "behavioral_context",
    "behavioral_relationship",
]
STRUCTURAL_ANCHORS = [
    "structural_topology",
    "structural_protocol",
    "structural_payload",
    "structural_flow",
]
ALL_ANCHORS = TEMPORAL_ANCHORS + BEHAVIORAL_ANCHORS + STRUCTURAL_ANCHORS


@dataclass
class CognitiveState:
    cell_id: str
    source_ip: str = ""
    timestamps: list[float] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)
    methods: set[str] = field(default_factory=set)
    user_agents: set[str] = field(default_factory=set)
    tool_signatures: set[str] = field(default_factory=set)
    injection_count: int = 0
    bait_hits: int = 0
    interaction_count: int = 0
    escalation_level: int = 0
    protocol_completeness: list[float] = field(default_factory=list)
    last_emit_at: float = 0.0


class CognitiveAgent(Agent):
    """Multi-anchor cognitive interpretation agent."""

    name = "cognitive"

    def __init__(self, decision_substrate: Substrate, hid_substrate: Substrate | None = None):
        super().__init__(decision_substrate)
        self._states: dict[str, CognitiveState] = {}
        self._hid_substrate = hid_substrate
        self._latest_hid_attestation: dict = {}
        self._update_counts: dict[str, int] = {}
        self._emit_every = 3

    def consume(self, record: SubstrateRecord) -> None:
        if record.substrate == "hid":
            self._latest_hid_attestation = record.payload
            return

        if not record.cell_id:
            return

        state = self._states.get(record.cell_id)
        if not state:
            state = CognitiveState(cell_id=record.cell_id)
            self._states[record.cell_id] = state

        if record.substrate == "ingress" and record.record_type == "http_request":
            self._update_from_ingress(state, record.payload)
        elif record.substrate == "mirror":
            self._update_from_mirror(state, record.record_type, record.payload)
        else:
            return

        self._update_counts[record.cell_id] = self._update_counts.get(record.cell_id, 0) + 1
        if self._update_counts[record.cell_id] % self._emit_every == 0:
            self._emit_assessment(state)

    def tick(self) -> None:
        for state in self._states.values():
            if state.interaction_count >= 1 and (time.time() - state.last_emit_at) > 30:
                self._emit_assessment(state)

    def get_assessment(self, cell_id: str) -> dict | None:
        state = self._states.get(cell_id)
        return self._build_assessment(state) if state else None

    def _update_from_ingress(self, state: CognitiveState, payload: dict) -> None:
        state.source_ip = payload.get("source_ip", state.source_ip)
        state.timestamps.append(time.time())
        state.paths.append(payload.get("path", ""))
        state.methods.add(payload.get("method", ""))
        user_agent = payload.get("user_agent", "")
        if user_agent:
            state.user_agents.add(user_agent)

        protocol_signals = payload.get("protocol_signals", {})
        completeness = 0.0
        if protocol_signals:
            completeness = sum(1 for value in protocol_signals.values() if value) / len(protocol_signals)
        state.protocol_completeness.append(completeness)

        query_string = payload.get("query_string", "")
        injection = detect_injection_attempt(
            payload.get("path", ""),
            payload.get("body_preview", ""),
            query_string,
        )
        if injection:
            state.injection_count += 1

        path_lower = payload.get("path", "").lower()
        if any(
            bait in path_lower
            for bait in ("/admin", "/.env", "/api/keys", "/backup", "/config", "/internal", "/secret")
        ):
            state.bait_hits += 1

    def _update_from_mirror(self, state: CognitiveState, record_type: str, payload: dict) -> None:
        if record_type == "interaction":
            state.interaction_count = payload.get("interaction_count", state.interaction_count)
            tool_signature = payload.get("tool_signature", "")
            if tool_signature:
                state.tool_signatures.add(tool_signature)
        elif record_type == "escalation":
            state.escalation_level = payload.get("new_level", state.escalation_level)
            for tool_signature in payload.get("tools_seen", []):
                if tool_signature:
                    state.tool_signatures.add(tool_signature)
            state.injection_count = max(state.injection_count, payload.get("injection_attempts", 0))

    def _emit_assessment(self, state: CognitiveState) -> None:
        assessment = self._build_assessment(state)
        state.last_emit_at = time.time()
        self.emit(
            AgentDecision(
                agent_name=self.name,
                decision_type="cognitive_assessment",
                confidence=assessment["confidence"],
                cell_id=state.cell_id,
                reasoning=(
                    f"threat={assessment['threat_score']:.2f} "
                    f"human={assessment['human_likelihood']:.2f} "
                    f"authenticity={assessment['authenticity']:.2f} "
                    f"coherence={assessment['cognitive_coherence']:.2f} "
                    f"consensus={assessment['consensus_strength']:.2f}"
                ),
                recommended_action=(
                    "escalate_cognitive" if assessment["threat_score"] >= 0.7 else "observe"
                ),
                context=assessment,
            )
        )

    def _build_assessment(self, state: CognitiveState) -> dict:
        anchors = self._score_anchors(state)
        scores = [item["score"] for item in anchors.values()]
        confidences = [item["confidence"] for item in anchors.values()]
        mean_score = sum(scores) / len(scores) if scores else 0.5
        mean_confidence = sum(confidences) / len(confidences) if confidences else 0.0

        variance = statistics.pvariance(scores) if len(scores) > 1 else 0.0
        consensus_strength = max(0.0, 1.0 - min(1.0, variance * 2.0))
        anomaly_ratio = (
            sum(1 for score in scores if score < 0.35) / len(scores)
            if scores else 0.0
        )
        cognitive_coherence = 1.0 / (1.0 + variance * 10.0)

        temporal_score = self._average_anchor_group(anchors, TEMPORAL_ANCHORS)
        behavioral_score = self._average_anchor_group(anchors, BEHAVIORAL_ANCHORS)
        structural_score = self._average_anchor_group(anchors, STRUCTURAL_ANCHORS)

        authenticity = (temporal_score + behavioral_score + structural_score) / 3.0
        human_likelihood = max(0.0, min(1.0, (temporal_score + behavioral_score + cognitive_coherence) / 3.0))

        hid_context = self._latest_hid_summary()
        if hid_context.get("active_human"):
            human_likelihood = min(1.0, human_likelihood + 0.15)
            authenticity = min(1.0, authenticity + 0.05)

        threat_score = min(
            1.0,
            max(
                0.0,
                (1.0 - authenticity) * 0.55
                + anomaly_ratio * 0.25
                + (0.15 if state.injection_count > 0 else 0.0)
                + (0.10 if state.escalation_level >= 3 else 0.0),
            ),
        )

        confidence = min(1.0, max(0.2, mean_confidence * 0.7 + consensus_strength * 0.3))

        return {
            "cell_id": state.cell_id,
            "source_ip": state.source_ip,
            "anchor_scores": anchors,
            "resonance_vector": {
                "source_resonance": structural_score,
                "destination_resonance": behavioral_score,
                "protocol_resonance": structural_score,
                "temporal_resonance": temporal_score,
                "behavioral_resonance": behavioral_score,
                "structural_resonance": structural_score,
                "cognitive_coherence": round(cognitive_coherence, 3),
                "threat_level": round(threat_score, 3),
                "confidence": round(confidence, 3),
                "authenticity": round(authenticity, 3),
                "consistency": round(consensus_strength, 3),
                "predictability": round(max(0.0, 1.0 - variance), 3),
                "human_likelihood": round(human_likelihood, 3),
            },
            "consensus_strength": round(consensus_strength, 3),
            "anomaly_ratio": round(anomaly_ratio, 3),
            "cognitive_coherence": round(cognitive_coherence, 3),
            "authenticity": round(authenticity, 3),
            "human_likelihood": round(human_likelihood, 3),
            "threat_score": round(threat_score, 3),
            "confidence": round(confidence, 3),
            "hid_attestation": hid_context,
            "interaction_count": state.interaction_count,
            "injection_count": state.injection_count,
            "tool_count": len(state.tool_signatures),
            "unique_paths": len(set(state.paths)),
        }

    def _score_anchors(self, state: CognitiveState) -> dict[str, dict[str, float]]:
        timestamps = state.timestamps[-20:]
        intervals = [
            timestamps[i + 1] - timestamps[i]
            for i in range(len(timestamps) - 1)
        ] if len(timestamps) > 1 else []
        unique_paths = len(set(state.paths))
        total_paths = len(state.paths)
        repeated_path_ratio = 0.0
        if total_paths > 0:
            repeated_path_ratio = 1.0 - (unique_paths / total_paths)

        protocol_avg = (
            sum(state.protocol_completeness) / len(state.protocol_completeness)
            if state.protocol_completeness else 0.0
        )

        temporal_rhythm_score, temporal_rhythm_conf = self._temporal_rhythm(intervals)
        cadence_score = self._clamp(1.0 - repeated_path_ratio)
        sequence_score = self._clamp(unique_paths / max(1, min(total_paths, 8)))
        duration_score = self._clamp(min(1.0, total_paths / 12.0))

        behavioral_intent = self._clamp(0.35 + min(unique_paths, 6) / 10.0)
        behavioral_pattern = self._clamp(1.0 - min(1.0, repeated_path_ratio * 1.25))
        behavioral_context = self._clamp(1.0 - min(1.0, state.injection_count * 0.35))
        behavioral_relationship = self._clamp((len(state.methods) + len(state.tool_signatures) + 1) / 6.0)

        structural_topology = self._clamp(0.8 if state.source_ip else 0.3)
        structural_protocol = self._clamp(protocol_avg or 0.25)
        structural_payload = self._clamp(1.0 - min(1.0, state.injection_count * 0.4))
        structural_flow = self._clamp(1.0 - self._timing_regularity(intervals))

        return {
            "temporal_rhythm": {"score": temporal_rhythm_score, "confidence": temporal_rhythm_conf},
            "temporal_cadence": {"score": cadence_score, "confidence": self._confidence_from_count(total_paths, 3)},
            "temporal_sequence": {"score": sequence_score, "confidence": self._confidence_from_count(unique_paths, 3)},
            "temporal_duration": {"score": duration_score, "confidence": self._confidence_from_count(total_paths, 4)},
            "behavioral_intent": {"score": behavioral_intent, "confidence": self._confidence_from_count(total_paths, 4)},
            "behavioral_pattern": {"score": behavioral_pattern, "confidence": self._confidence_from_count(total_paths, 4)},
            "behavioral_context": {"score": behavioral_context, "confidence": self._confidence_from_count(total_paths, 2)},
            "behavioral_relationship": {"score": behavioral_relationship, "confidence": self._confidence_from_count(len(state.tool_signatures) + len(state.methods), 2)},
            "structural_topology": {"score": structural_topology, "confidence": 0.8 if state.source_ip else 0.1},
            "structural_protocol": {"score": structural_protocol, "confidence": self._confidence_from_count(len(state.protocol_completeness), 3)},
            "structural_payload": {"score": structural_payload, "confidence": self._confidence_from_count(total_paths, 2)},
            "structural_flow": {"score": structural_flow, "confidence": temporal_rhythm_conf},
        }

    def _latest_hid_summary(self) -> dict:
        if self._hid_substrate and hasattr(self._hid_substrate, "get_recent_attestation"):
            try:
                attestation = self._hid_substrate.get_recent_attestation()
                if attestation:
                    return {
                        "available": bool(attestation.get("available", False)),
                        "active_human": bool(attestation.get("active_human", False)),
                        "confidence": float(attestation.get("confidence", 0.0)),
                        "idle_seconds": attestation.get("idle_seconds", 0.0),
                        "session_locked": bool(attestation.get("session_locked", False)),
                    }
            except Exception:
                pass

        payload = self._latest_hid_attestation or {}
        if not payload:
            return {"available": False, "active_human": False, "confidence": 0.0}

        activity = (
            payload.get("key_event_count", 0) > 0
            or payload.get("click_count", 0) > 0
            or payload.get("movement_detected", False)
        )
        session_locked = payload.get("session_locked", False)
        idle_seconds = payload.get("idle_seconds", 0.0)
        active_human = activity and not session_locked and idle_seconds <= 120

        confidence = 0.0
        if active_human:
            confidence = 0.65
            if payload.get("key_event_count", 0) > 0:
                confidence += 0.15
            if payload.get("click_count", 0) > 0 or payload.get("movement_detected", False):
                confidence += 0.10

        return {
            "available": True,
            "active_human": active_human,
            "confidence": min(1.0, confidence),
            "idle_seconds": idle_seconds,
            "session_locked": session_locked,
        }

    @staticmethod
    def _average_anchor_group(anchors: dict[str, dict[str, float]], names: list[str]) -> float:
        scores = [anchors[name]["score"] for name in names]
        return sum(scores) / len(scores) if scores else 0.5

    @staticmethod
    def _confidence_from_count(count: int, threshold: int) -> float:
        if threshold <= 0:
            return 1.0
        return min(1.0, max(0.1, count / threshold))

    @staticmethod
    def _clamp(value: float) -> float:
        return min(1.0, max(0.0, value))

    def _temporal_rhythm(self, intervals: list[float]) -> tuple[float, float]:
        if len(intervals) < 2:
            return 0.5, 0.1

        mean_interval = sum(intervals) / len(intervals)
        if mean_interval <= 0:
            return 0.0, 0.8

        variance = statistics.pvariance(intervals)
        score = min(1.0, variance / (mean_interval * 0.1))
        confidence = min(1.0, len(intervals) / 5.0)
        return self._clamp(score), confidence

    def _timing_regularity(self, intervals: list[float]) -> float:
        if len(intervals) < 2:
            return 0.0
        mean_interval = sum(intervals) / len(intervals)
        if mean_interval <= 0:
            return 1.0
        variance = statistics.pvariance(intervals)
        std_dev = variance ** 0.5
        cv = std_dev / mean_interval
        return self._clamp(1.0 - min(1.0, cv))
