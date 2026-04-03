import time
import unittest
from pathlib import Path

from securecore.chat.ledger import ChatLedger


class ChatLedgerTests(unittest.TestCase):
    def test_start_conversation_append_and_verify(self):
        temp_root = Path(".test_tmp")
        temp_root.mkdir(exist_ok=True)
        ledger_path = temp_root / f"chat_ledger_{time.time_ns()}.jsonl"
        try:
            ledger = ChatLedger(ledger_path)
            ledger.start_conversation("conv_1", "support")
            ledger.ensure_branch("conv_1", mode="support")
            first = ledger.append_message(
                conversation_id="conv_1",
                branch_id="main",
                mode="support",
                role="operator",
                content="hello",
            )
            second = ledger.append_message(
                conversation_id="conv_1",
                branch_id="main",
                mode="support",
                role="assistant",
                content="hi",
            )

            self.assertEqual(first.sequence, 2)
            self.assertEqual(second.sequence, 3)
            self.assertEqual(second.previous_hash, first.chain_hash)
            self.assertTrue(ledger.verify_chain()["intact"])
        finally:
            ledger_path.unlink(missing_ok=True)

    def test_tail_messages_filters_by_conversation_and_branch(self):
        temp_root = Path(".test_tmp")
        temp_root.mkdir(exist_ok=True)
        ledger_path = temp_root / f"chat_ledger_{time.time_ns()}.jsonl"
        try:
            ledger = ChatLedger(ledger_path)
            ledger.start_conversation("conv_1", "support")
            ledger.ensure_branch("conv_1", mode="support")
            ledger.append_message(
                conversation_id="conv_1",
                branch_id="main",
                mode="support",
                role="operator",
                content="first",
            )
            ledger.start_conversation("conv_2", "build")
            ledger.ensure_branch("conv_2", mode="build")
            ledger.append_message(
                conversation_id="conv_2",
                branch_id="main",
                mode="build",
                role="operator",
                content="second",
            )

            messages = ledger.tail_messages("conv_1")
            self.assertEqual(len(messages), 1)
            self.assertEqual(messages[0].payload["content"], "first")
        finally:
            ledger_path.unlink(missing_ok=True)

    def test_branch_history_includes_parent_path_and_annotations_are_appended(self):
        temp_root = Path(".test_tmp")
        temp_root.mkdir(exist_ok=True)
        ledger_path = temp_root / f"chat_ledger_{time.time_ns()}.jsonl"
        try:
            ledger = ChatLedger(ledger_path)
            ledger.start_conversation("conv_1", "support")
            ledger.ensure_branch("conv_1", mode="support")
            root = ledger.append_message(
                conversation_id="conv_1",
                branch_id="main",
                mode="support",
                role="operator",
                content="First paragraph.\n\nSecond paragraph.",
            )
            branch = ledger.create_branch(
                conversation_id="conv_1",
                mode="build",
                parent_message_id=root.message_id,
                parent_branch_id="main",
                parent_block_id="b1",
            )
            branch_msg = ledger.append_message(
                conversation_id="conv_1",
                branch_id=branch.branch_id,
                mode="build",
                role="operator",
                content="Branch reply.",
            )
            note = ledger.append_note(
                conversation_id="conv_1",
                branch_id="main",
                mode="support",
                message_id=root.message_id,
                block_id="b0",
                block_index=0,
                content="Watch this block.",
            )
            cite = ledger.append_citation(
                conversation_id="conv_1",
                branch_id="main",
                mode="support",
                message_id=root.message_id,
                block_id="b1",
                block_index=1,
                source_type="file",
                source_ref="securecore/help/bot.py",
                excerpt="help bot grounding",
            )

            visible = ledger.conversation_messages("conv_1", branch_id=branch.branch_id)

            self.assertEqual([record.message_id for record in visible], [root.message_id, branch_msg.message_id])
            self.assertEqual(note.entry_type, "note")
            self.assertEqual(cite.entry_type, "citation")
            self.assertTrue(ledger.verify_chain()["intact"])
        finally:
            ledger_path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
