"""Weighted confidence validation for SecureCore decisions.

This is intentionally small and pure Python. It borrows the useful part of
multi-stage validation systems: multiple signals, weighted scoring, explicit
threshold tiers, and an audit-friendly breakdown of how a score was reached.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class ConfidenceSignal:
    """One weighted contributor to a confidence decision."""

    name: str
    score: float
    weight: float = 1.0
    present: bool = True
    details: dict[str, Any] = field(default_factory=dict)

    def normalized_score(self) -> float:
        return min(1.0, max(0.0, float(self.score)))

    def normalized_weight(self) -> float:
        return max(0.0, float(self.weight))


@dataclass(slots=True)
class ConfidenceAssessment:
    score: float
    tier: str
    actionable: bool
    total_weight: float
    contributors: list[dict[str, Any]]


class ConfidenceValidator:
    """Compute weighted confidence and classify it into action tiers."""

    DEFAULT_THRESHOLDS = {
        "auto_act": 0.95,
        "high": 0.85,
        "review": 0.70,
        "cautious": 0.50,
    }

    def __init__(self, thresholds: dict[str, float] | None = None):
        self.thresholds = dict(self.DEFAULT_THRESHOLDS)
        if thresholds:
            self.thresholds.update(thresholds)

    def assess(self, signals: list[ConfidenceSignal]) -> ConfidenceAssessment:
        contributors = []
        weighted_sum = 0.0
        total_weight = 0.0

        for signal in signals:
            if not signal.present or signal.normalized_weight() <= 0:
                continue

            score = signal.normalized_score()
            weight = signal.normalized_weight()
            weighted_sum += score * weight
            total_weight += weight
            contributors.append(
                {
                    "name": signal.name,
                    "score": score,
                    "weight": weight,
                    "details": signal.details,
                }
            )

        final_score = (weighted_sum / total_weight) if total_weight else 0.0
        tier = self.tier_for(final_score)
        actionable = final_score >= self.thresholds["review"]

        return ConfidenceAssessment(
            score=final_score,
            tier=tier,
            actionable=actionable,
            total_weight=total_weight,
            contributors=contributors,
        )

    def tier_for(self, score: float) -> str:
        score = min(1.0, max(0.0, float(score)))
        if score >= self.thresholds["auto_act"]:
            return "auto_act"
        if score >= self.thresholds["high"]:
            return "high"
        if score >= self.thresholds["review"]:
            return "review"
        if score >= self.thresholds["cautious"]:
            return "cautious"
        return "reject"
