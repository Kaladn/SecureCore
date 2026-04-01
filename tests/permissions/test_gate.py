"""Tests for the permission gate — the single enforcement chokepoint."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from securecore.permissions.registry import CallerRegistry
from securecore.permissions.gate import PermissionGate, PermissionDenied, WriteToken
from securecore.substrates.ingress import IngressSubstrate
from securecore.substrates.agent_decisions import AgentDecisionsSubstrate
from securecore.permissions.types import SubstrateWriter


# Valid ingress payload that passes schema validation
VALID_INGRESS = {
    "source_ip": "1.2.3.4",
    "method": "GET",
    "path": "/.env",
}


class TestPermissionGate(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.registry = CallerRegistry()
        self.gate = PermissionGate(self.registry)

        self.trap_entry = self.registry.register(
            caller_id="routes:traps",
            caller_type="routes",
            module_path="securecore.decoys.routes",
            allowed_write=["ingress"],
            allowed_read=[],
        )

        self.agent_entry = self.registry.register(
            caller_id="agent:watcher",
            caller_type="agent",
            module_path="securecore.agents.watcher",
            allowed_write=["agent_decisions"],
            allowed_read=["ingress"],
        )

        self.ingress = IngressSubstrate(os.path.join(self.tmpdir, "subs"))
        self.ingress.set_permission_gate(self.gate)

        self.decisions = AgentDecisionsSubstrate(os.path.join(self.tmpdir, "subs"))
        self.decisions.set_permission_gate(self.gate)

    def test_authorized_write_succeeds(self):
        """Trap routes can write to ingress."""
        token = WriteToken(
            caller_id="routes:traps",
            record_type="http_request",
            payload=VALID_INGRESS,
            signing_key=self.trap_entry.signing_key,
        )
        record = self.ingress.append(
            record_type="http_request",
            payload=dict(VALID_INGRESS),
            write_token=token,
        )
        self.assertEqual(record.payload["_caller_id"], "routes:traps")
        self.assertEqual(record.payload["path"], "/.env")

    def test_unauthorized_write_denied(self):
        """Agent cannot write to ingress — denied before schema check."""
        token = WriteToken(
            caller_id="agent:watcher",
            record_type="http_request",
            payload=VALID_INGRESS,
            signing_key=self.agent_entry.signing_key,
        )
        with self.assertRaises(PermissionDenied) as ctx:
            self.ingress.append(
                record_type="http_request",
                payload=dict(VALID_INGRESS),
                write_token=token,
            )
        self.assertIn("not in allowed_write", str(ctx.exception))

    def test_unregistered_caller_denied(self):
        """Unregistered caller is denied before schema check."""
        token = WriteToken(
            caller_id="rogue:attacker",
            record_type="http_request",
            payload=VALID_INGRESS,
            signing_key=os.urandom(32),
        )
        with self.assertRaises(PermissionDenied) as ctx:
            self.ingress.append(
                record_type="http_request",
                payload=dict(VALID_INGRESS),
                write_token=token,
            )
        self.assertIn("unregistered", str(ctx.exception))

    def test_spoofed_signature_denied(self):
        """Valid caller_id but wrong signing key is denied."""
        token = WriteToken(
            caller_id="routes:traps",
            record_type="http_request",
            payload=VALID_INGRESS,
            signing_key=os.urandom(32),  # wrong key
        )
        with self.assertRaises(PermissionDenied) as ctx:
            self.ingress.append(
                record_type="http_request",
                payload=dict(VALID_INGRESS),
                write_token=token,
            )
        self.assertIn("invalid signature", str(ctx.exception))

    def test_no_token_denied(self):
        """Write without a token is denied when gate is set."""
        with self.assertRaises(PermissionDenied) as ctx:
            self.ingress.append(
                record_type="http_request",
                payload=dict(VALID_INGRESS),
            )
        self.assertIn("no write_token", str(ctx.exception))

    def test_denial_counter_increments(self):
        """Denied writes increment the caller's denial counter."""
        for _ in range(3):
            token = WriteToken(
                caller_id="agent:watcher",
                record_type="http_request",
                payload=VALID_INGRESS,
                signing_key=self.agent_entry.signing_key,
            )
            try:
                self.ingress.append(
                    record_type="http_request",
                    payload=dict(VALID_INGRESS),
                    write_token=token,
                )
            except PermissionDenied:
                pass

        self.assertEqual(self.agent_entry.denied_count, 3)
        self.assertEqual(self.agent_entry.last_denied_target, "ingress")

    def test_agent_can_write_to_agent_decisions(self):
        """Agent writing to agent_decisions succeeds."""
        payload = {"agent_name": "watcher", "confidence": 0.9}
        token = WriteToken(
            caller_id="agent:watcher",
            record_type="agent_decision:test",
            payload=payload,
            signing_key=self.agent_entry.signing_key,
        )
        record = self.decisions.append(
            record_type="agent_decision:test",
            payload=dict(payload),
            write_token=token,
        )
        self.assertEqual(record.payload["_caller_id"], "agent:watcher")

    def test_substrate_writer_auto_signs(self):
        """SubstrateWriter creates and signs tokens automatically."""
        writer = SubstrateWriter(self.ingress, "routes:traps", self.trap_entry.signing_key)
        record = writer.append(
            record_type="http_request",
            payload=dict(VALID_INGRESS),
        )
        self.assertEqual(record.payload["_caller_id"], "routes:traps")
        self.assertEqual(record.payload["path"], "/.env")

    def test_substrate_writer_delegates_specific_methods(self):
        """SubstrateWriter delegates substrate-specific methods through the gate."""
        writer = SubstrateWriter(self.ingress, "routes:traps", self.trap_entry.signing_key)
        record = writer.record_request(
            source_ip="1.2.3.4",
            source_port=12345,
            method="GET",
            path="/.env",
            query_string="",
            headers={"User-Agent": "test"},
            body="",
        )
        self.assertEqual(record.payload["_caller_id"], "routes:traps")
        self.assertEqual(record.payload["source_ip"], "1.2.3.4")

    def test_denial_log_accessible(self):
        """Gate maintains a denial log."""
        token = WriteToken(
            caller_id="agent:watcher",
            record_type="test",
            payload={},
            signing_key=self.agent_entry.signing_key,
        )
        try:
            self.ingress.append(record_type="test", payload={}, write_token=token)
        except PermissionDenied:
            pass

        denials = self.gate.recent_denials()
        self.assertEqual(len(denials), 1)
        self.assertEqual(denials[0]["caller_id"], "agent:watcher")
        self.assertEqual(denials[0]["substrate"], "ingress")

    def test_payload_mismatch_denied(self):
        """Token signed for one payload cannot authorize a different payload."""
        original_payload = dict(VALID_INGRESS)
        token = WriteToken(
            caller_id="routes:traps",
            record_type="http_request",
            payload=original_payload,
            signing_key=self.trap_entry.signing_key,
        )
        # Try to write a DIFFERENT payload with the same token
        tampered_payload = dict(VALID_INGRESS)
        tampered_payload["path"] = "/evil"
        with self.assertRaises(PermissionDenied) as ctx:
            self.ingress.append(
                record_type="http_request",
                payload=tampered_payload,
                write_token=token,
            )
        self.assertIn("payload hash mismatch", str(ctx.exception))

    def test_concurrent_delegated_writes_isolated(self):
        """Concurrent delegated writes via SubstrateWriter should not cross-contaminate tokens."""
        import threading

        writer_a = SubstrateWriter(self.decisions, "agent:watcher", self.agent_entry.signing_key)

        errors = []
        results = []

        def write_decision(writer, name, index):
            try:
                record = writer.append(
                    record_type=f"agent_decision:test_{index}",
                    payload={"agent_name": name, "confidence": 0.5, "index": index},
                )
                results.append(record)
            except Exception as exc:
                errors.append(exc)

        threads = []
        for i in range(10):
            t = threading.Thread(target=write_decision, args=(writer_a, "watcher", i))
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Concurrent write errors: {errors}")
        self.assertEqual(len(results), 10)
        # Every record should have the correct caller_id
        for record in results:
            self.assertEqual(record.payload["_caller_id"], "agent:watcher")

    def test_caller_identity_immutable_in_record(self):
        """Verified caller_id is embedded in the record payload and cannot be overridden."""
        payload = dict(VALID_INGRESS)
        payload["_caller_id"] = "evil:impersonator"  # attacker tries to set it
        token = WriteToken(
            caller_id="routes:traps",
            record_type="http_request",
            payload=payload,
            signing_key=self.trap_entry.signing_key,
        )
        record = self.ingress.append(
            record_type="http_request",
            payload=payload,
            write_token=token,
        )
        # Gate should overwrite the attacker's fake _caller_id
        self.assertEqual(record.payload["_caller_id"], "routes:traps")


if __name__ == "__main__":
    unittest.main()
