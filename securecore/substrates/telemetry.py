"""Telemetry Substrate - high-volume operational data.

This substrate handles the firehose: every metric, timing measurement,
throughput counter, and performance signal. It's designed for volume -
lightweight records, fast appends, periodic rollups.

Telemetry feeds the health dashboard and enables replay analysis.
It is NOT evidence-grade - it's operational truth about system behavior.
"""

import time
import threading
from typing import Optional

from securecore.substrates.base import Substrate


class TelemetrySubstrate(Substrate):
    """High-volume operational telemetry substrate."""

    name = "telemetry"

    def __init__(self, data_dir: str):
        super().__init__(data_dir)
        self._rollup_lock = threading.Lock()
        self._rollup_counters: dict[str, float] = {}
        self._rollup_counts: dict[str, int] = {}

    def record_metric(
        self,
        metric_name: str,
        value: float,
        component: str,
        cell_id: str = "",
        tags: Optional[dict] = None,
    ) -> "SubstrateRecord":
        """Record a single metric measurement."""
        payload = {
            "metric_name": metric_name,
            "value": value,
            "component": component,
            "epoch_ns": time.time_ns(),
            "tags": tags or {},
        }
        # Accumulate for rollups
        with self._rollup_lock:
            key = f"{component}:{metric_name}"
            self._rollup_counters[key] = self._rollup_counters.get(key, 0.0) + value
            self._rollup_counts[key] = self._rollup_counts.get(key, 0) + 1

        return self.append(record_type="metric", payload=payload, cell_id=cell_id)

    def record_timing(
        self,
        operation: str,
        duration_ms: float,
        component: str,
        cell_id: str = "",
        success: bool = True,
    ) -> "SubstrateRecord":
        """Record a timing measurement for an operation."""
        payload = {
            "operation": operation,
            "duration_ms": duration_ms,
            "component": component,
            "success": success,
            "epoch_ns": time.time_ns(),
        }
        return self.append(record_type="timing", payload=payload, cell_id=cell_id)

    def record_throughput(
        self,
        counter_name: str,
        count: int,
        component: str,
        window_seconds: float = 1.0,
    ) -> "SubstrateRecord":
        """Record a throughput measurement."""
        payload = {
            "counter_name": counter_name,
            "count": count,
            "rate_per_second": count / window_seconds if window_seconds > 0 else 0,
            "component": component,
            "window_seconds": window_seconds,
            "epoch_ns": time.time_ns(),
        }
        return self.append(record_type="throughput", payload=payload)

    def flush_rollups(self) -> list["SubstrateRecord"]:
        """Flush accumulated rollup counters as rollup records."""
        records = []
        with self._rollup_lock:
            for key, total in self._rollup_counters.items():
                component, metric = key.split(":", 1)
                count = self._rollup_counts.get(key, 0)
                avg = total / count if count > 0 else 0

                record = self.append(
                    record_type="rollup",
                    payload={
                        "metric_name": metric,
                        "component": component,
                        "total": total,
                        "count": count,
                        "average": avg,
                        "epoch_ns": time.time_ns(),
                    },
                )
                records.append(record)

            self._rollup_counters.clear()
            self._rollup_counts.clear()

        return records

    def get_latest_metrics(self, component: str = "", limit: int = 100) -> list[dict]:
        """Get latest metric records, optionally filtered by component."""
        records = self.query(record_type="metric", limit=limit)
        if component:
            records = [r for r in records if r.payload.get("component") == component]
        return [r.to_dict() for r in records]
