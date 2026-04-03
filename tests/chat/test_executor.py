import time
import unittest
from pathlib import Path

from securecore.chat.executor import ChatExecutor
from securecore.chat.ledger import ChatLedger


class _FakeHelpBot:
    def ask(self, question: str, include_runtime: bool = True) -> dict:
        return {
            "answer": f"support:{question}",
            "basis": ["help.reaper"],
            "file_refs": ["securecore/help/bot.py"],
            "commands": ["python -m securecore.cli.main help reaper"],
            "unknowns": [],
            "sources": {"runtime_included": include_runtime},
            "structured": True,
            "context_bundle_hash": "abc123",
            "model": "local-model",
        }


class _FakeBroker:
    def __init__(self):
        self.calls = []

    def query(self, role_name: str, prompt: str, context_bundle, temperature: float = 0.0, max_tokens: int = 0):
        self.calls.append(
            {
                "role_name": role_name,
                "prompt": prompt,
                "sources": [block.source_label for block in context_bundle.blocks],
                "contents": [block.content for block in context_bundle.blocks],
                "temperature": temperature,
                "max_tokens": max_tokens,
            }
        )
        return f"{role_name}:{prompt}"

    def get_role(self, role_name: str):
        class _Role:
            def __init__(self, model: str):
                self.model = model

        return _Role("local-model") if role_name in {"operations", "build"} else None


class ChatExecutorTests(unittest.TestCase):
    def test_support_mode_writes_to_ledger_and_returns_help_fields(self):
        temp_root = Path(".test_tmp")
        temp_root.mkdir(exist_ok=True)
        ledger_path = temp_root / f"chat_ledger_{time.time_ns()}.jsonl"
        try:
            ledger = ChatLedger(ledger_path)
            executor = ChatExecutor(ledger, _FakeHelpBot(), _FakeBroker())

            result = executor.send(message="what is reaper", mode="support")

            self.assertEqual(result["mode"], "support")
            self.assertEqual(result["response"], "support:what is reaper")
            self.assertEqual(result["basis"], ["help.reaper"])
            self.assertEqual(len(ledger.tail_messages(result["conversation_id"])), 2)
        finally:
            ledger_path.unlink(missing_ok=True)

    def test_operations_and_build_modes_use_broker_roles(self):
        temp_root = Path(".test_tmp")
        temp_root.mkdir(exist_ok=True)
        ledger_path = temp_root / f"chat_ledger_{time.time_ns()}.jsonl"
        try:
            ledger = ChatLedger(ledger_path)
            broker = _FakeBroker()
            executor = ChatExecutor(ledger, _FakeHelpBot(), broker)

            op = executor.send(message="status", mode="operations")
            build = executor.send(message="make route", mode="build")

            self.assertEqual(op["response"], "operations:status")
            self.assertEqual(build["response"], "build:make route")
            self.assertEqual([call["role_name"] for call in broker.calls], ["operations", "build"])
            self.assertEqual(broker.calls[0]["temperature"], 0.1)
            self.assertEqual(broker.calls[1]["max_tokens"], 1600)
        finally:
            ledger_path.unlink(missing_ok=True)

    def test_history_notes_citations_and_continue_branch_are_projected(self):
        temp_root = Path(".test_tmp")
        temp_root.mkdir(exist_ok=True)
        ledger_path = temp_root / f"chat_ledger_{time.time_ns()}.jsonl"
        try:
            ledger = ChatLedger(ledger_path)
            broker = _FakeBroker()
            executor = ChatExecutor(ledger, _FakeHelpBot(), broker)

            root = executor.send(
                message="First paragraph.\n\nSecond paragraph.",
                mode="support",
            )
            executor.add_note(
                conversation_id=root["conversation_id"],
                message_id=root["message_ids"]["assistant"],
                block_id="b0",
                content="keep this in mind",
            )
            executor.add_citation(
                conversation_id=root["conversation_id"],
                message_id=root["message_ids"]["assistant"],
                block_id="b1",
                source_type="file",
                source_ref="securecore/help/bot.py",
                excerpt="grounded help",
            )
            branch = executor.continue_chat(
                conversation_id=root["conversation_id"],
                parent_message_id=root["message_ids"]["assistant"],
                parent_block_id="b1",
                mode="build",
            )

            branch_send = executor.send(
                message="Carry forward from here.",
                mode="build",
                conversation_id=root["conversation_id"],
                branch_id=branch["branch_id"],
            )
            history = executor.history(
                conversation_id=root["conversation_id"],
                branch_id=branch["branch_id"],
            )

            self.assertEqual(branch_send["mode"], "build")
            self.assertEqual(len(history["messages"]), 4)
            assistant_blocks = history["messages"][1]["blocks"]
            self.assertEqual(assistant_blocks[0]["note_count"], 1)
            self.assertEqual(assistant_blocks[1]["citation_count"], 1)
            self.assertTrue(any("First paragraph." in content for content in broker.calls[-1]["contents"]))
        finally:
            ledger_path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
