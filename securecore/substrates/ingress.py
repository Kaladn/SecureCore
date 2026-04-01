"""Ingress Substrate - raw request capture.

This is the first thing that touches an incoming request. Before any
interpretation, classification, or agent processing, the raw ingress
fact is recorded here.

Every field captured:
  - source IP and port
  - HTTP method, path, query string
  - full headers (as-received)
  - body hash and size (body stored separately if large)
  - timing: arrival timestamp at microsecond precision
  - protocol fingerprint: HTTP version, connection behavior
  - socket metadata: keep-alive, connection reuse indicators
"""

import hashlib
import time
from typing import Optional

from securecore.substrates.base import Substrate


class IngressSubstrate(Substrate):
    """Raw request capture substrate."""

    name = "ingress"

    def validate_payload(self, record_type: str, payload: dict) -> None:
        if record_type == "http_request":
            required = {"source_ip", "method", "path"}
            missing = required - set(payload.keys())
            if missing:
                raise ValueError(f"ingress http_request missing: {missing}")

    def record_request(
        self,
        source_ip: str,
        source_port: Optional[int],
        method: str,
        path: str,
        query_string: str,
        headers: dict,
        body: str,
        cell_id: str = "",
    ) -> "SubstrateRecord":
        """Record a raw incoming request."""
        body_bytes = body.encode("utf-8") if isinstance(body, str) else body
        body_hash = hashlib.sha256(body_bytes).hexdigest()

        # Extract protocol fingerprint signals
        headers_lower = {k.lower(): v for k, v in headers.items()}
        connection = headers_lower.get("connection", "")
        user_agent = headers_lower.get("user-agent", "")
        accept = headers_lower.get("accept", "")
        content_type = headers_lower.get("content-type", "")

        payload = {
            "source_ip": source_ip,
            "source_port": source_port,
            "method": method,
            "path": path,
            "query_string": query_string,
            "headers": headers,
            "header_count": len(headers),
            "body_hash": body_hash,
            "body_size": len(body_bytes),
            "body_preview": body[:500] if body else "",
            "arrival_ns": time.time_ns(),
            "user_agent": user_agent,
            "accept": accept,
            "content_type": content_type,
            "connection_header": connection,
            "protocol_signals": {
                "has_user_agent": bool(user_agent),
                "has_accept": bool(accept),
                "has_accept_language": "accept-language" in headers_lower,
                "has_accept_encoding": "accept-encoding" in headers_lower,
                "has_referer": "referer" in headers_lower,
                "has_cookie": "cookie" in headers_lower,
                "has_origin": "origin" in headers_lower,
                "has_host": "host" in headers_lower,
                "keep_alive": connection.lower() == "keep-alive",
            },
        }

        return self.append(
            record_type="http_request",
            payload=payload,
            cell_id=cell_id,
        )

    def record_socket_event(
        self,
        event_type: str,
        source_ip: str,
        source_port: Optional[int],
        details: dict,
        cell_id: str = "",
    ) -> "SubstrateRecord":
        """Record a socket-level event (connect, disconnect, error)."""
        payload = {
            "event_type": event_type,
            "source_ip": source_ip,
            "source_port": source_port,
            "arrival_ns": time.time_ns(),
            **details,
        }
        return self.append(
            record_type="socket_event",
            payload=payload,
            cell_id=cell_id,
        )
