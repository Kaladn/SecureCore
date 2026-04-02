"""Tests for the strict LLMBroker Phase 1 behavior."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from securecore.llm.broker import LLMBroker
from securecore.llm.contexts.types import ContextBlock, ContextBundle


class _FakeAdapter:
    def __init__(self):
        self.calls = []

    def generate(self, prompt: str, system: str = "", temperature: float = 0.0, max_tokens: int = 2048):
        self.calls.append(
            {
                "prompt": prompt,
                "system": system,
                "temperature": temperature,
                "max_tokens": max_tokens,
            }
        )
        return "ok"

    def status(self) -> dict:
        return {"available": True}


class TestLLMBroker(unittest.TestCase):
    def setUp(self):
        self.broker = LLMBroker()
        self.fake_adapter = _FakeAdapter()

    def test_register_role_requires_registry_backed_entry(self):
        with self.assertRaises(ValueError):
            self.broker.register_role(
                role_name="help",
                caller_entry={},
                model="fake-model",
            )

    def test_query_uses_registry_reads_and_logs_bundle_identity(self):
        role = self.broker.register_role(
            role_name="help",
            caller_entry={
                "caller_id": "llm:help",
                "allowed_read": ["help_corpus", "code_index"],
            },
            model="fake-model",
            system_prompt="SYSTEM",
        )
        self.broker._adapters["fake-model"] = self.fake_adapter

        bundle = ContextBundle.build(
            [
                ContextBlock.build("code_index", "securecore/help/bot.py", 1, "CODE"),
                ContextBlock.build("help_corpus", "help_content.json", 0, "HELP"),
                ContextBlock.build("runtime_snapshot", "control_bus.status_snapshot", 2, "RUNTIME"),
            ]
        )

        response = self.broker.query(role_name="help", prompt="what is reaper", context_bundle=bundle)

        self.assertEqual(response, "ok")
        self.assertEqual(role.sequence, 1)
        self.assertEqual(len(self.fake_adapter.calls), 1)
        call = self.fake_adapter.calls[0]
        self.assertEqual(call["temperature"], 0.0)
        self.assertIn("[help_corpus]", call["prompt"])
        self.assertIn("[code_index]", call["prompt"])
        self.assertNotIn("[runtime_snapshot]", call["prompt"])

        interaction = self.broker.recent_interactions(1)[0]
        self.assertEqual(interaction["caller_id"], "llm:help")
        self.assertEqual(interaction["role"], "help")
        self.assertEqual(interaction["sequence"], 1)
        self.assertEqual(interaction["context_bundle_hash"], bundle.bundle_hash[:16])
        self.assertEqual(interaction["source_labels"], ["help_corpus", "code_index"])

    def test_query_rejects_oversized_context(self):
        self.broker.register_role(
            role_name="help",
            caller_entry={
                "caller_id": "llm:help",
                "allowed_read": ["help_corpus"],
            },
            model="fake-model",
            max_context_chars=5,
        )
        self.broker._adapters["fake-model"] = self.fake_adapter

        bundle = ContextBundle.build(
            [ContextBlock.build("help_corpus", "help_content.json", 0, "TOO LARGE")]
        )

        with self.assertRaises(ValueError):
            self.broker.query(role_name="help", prompt="q", context_bundle=bundle)
