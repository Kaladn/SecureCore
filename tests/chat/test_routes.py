import unittest

from flask import Flask
from flask_jwt_extended import JWTManager, create_access_token

from securecore.routes.chat import chat_bp


class _FakeExecutor:
    def __init__(self):
        self.calls = []

    def send(self, *, message: str, mode=None, conversation_id=None, branch_id=None):
        self.calls.append(
            {
                "message": message,
                "mode": mode,
                "conversation_id": conversation_id,
                "branch_id": branch_id,
            }
        )
        return {
            "conversation_id": "conv_1",
            "branch_id": "main",
            "mode": mode or "support",
            "response": "ok",
            "message_ids": {"user": "u1", "assistant": "a1"},
            "basis": [],
            "file_refs": [],
            "commands": [],
            "unknowns": [],
            "metadata": {},
            "inference": {"model": "local-model"},
            "trust": {"state": "FULL"},
        }

    def history(self, *, conversation_id: str, branch_id="main"):
        self.calls.append({"history": (conversation_id, branch_id)})
        return {
            "conversation_id": conversation_id,
            "branch_id": branch_id,
            "messages": [],
            "trust": {"state": "FULL"},
        }

    def add_note(self, *, conversation_id: str, message_id: str, block_id: str, content: str, branch_id=None):
        self.calls.append({"note": (conversation_id, message_id, block_id, content, branch_id)})
        return {"conversation_id": conversation_id, "message_id": message_id, "block_id": block_id, "note": {"note_id": "n1"}}

    def add_citation(self, *, conversation_id: str, message_id: str, block_id: str, source_type: str, source_ref: str, excerpt: str = "", branch_id=None):
        self.calls.append({"cite": (conversation_id, message_id, block_id, source_type, source_ref, excerpt, branch_id)})
        return {"conversation_id": conversation_id, "message_id": message_id, "block_id": block_id, "citation": {"citation_id": "c1"}}

    def continue_chat(self, *, conversation_id: str, parent_message_id: str, parent_block_id: str = "", mode=None, reason="continue_chat"):
        self.calls.append({"branch": (conversation_id, parent_message_id, parent_block_id, mode, reason)})
        return {"conversation_id": conversation_id, "branch_id": "branch_1", "parent_message_id": parent_message_id, "mode": mode or "support", "trust": {"state": "FULL"}}


class ChatRouteTests(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.config["JWT_SECRET_KEY"] = "test-secret"
        JWTManager(self.app)
        self.app.chat_executor = _FakeExecutor()
        self.app.register_blueprint(chat_bp)
        self.client = self.app.test_client()

        with self.app.app_context():
            self.token = create_access_token(identity="1", additional_claims={"role": "admin"})

    def test_chat_send_requires_message(self):
        resp = self.client.post(
            "/api/chat/send",
            json={},
            headers={"Authorization": f"Bearer {self.token}"},
        )
        self.assertEqual(resp.status_code, 400)

    def test_chat_send_dispatches_to_executor(self):
        resp = self.client.post(
            "/api/chat/send",
            json={"message": "hello", "mode": "support"},
            headers={"Authorization": f"Bearer {self.token}"},
        )
        self.assertEqual(resp.status_code, 200)
        payload = resp.get_json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["response"], "ok")
        self.assertEqual(self.app.chat_executor.calls[0]["message"], "hello")

    def test_history_note_cite_and_branch_routes_dispatch(self):
        history = self.client.get(
            "/api/chat/history?conversation_id=conv_1&branch_id=main",
            headers={"Authorization": f"Bearer {self.token}"},
        )
        self.assertEqual(history.status_code, 200)
        self.assertEqual(history.get_json()["conversation_id"], "conv_1")

        note = self.client.post(
            "/api/chat/note",
            json={
                "conversation_id": "conv_1",
                "message_id": "a1",
                "block_id": "b0",
                "content": "keep it",
            },
            headers={"Authorization": f"Bearer {self.token}"},
        )
        self.assertEqual(note.status_code, 200)
        self.assertEqual(note.get_json()["note"]["note_id"], "n1")

        cite = self.client.post(
            "/api/chat/cite",
            json={
                "conversation_id": "conv_1",
                "message_id": "a1",
                "block_id": "b0",
                "source_type": "file",
                "source_ref": "securecore/help/bot.py",
            },
            headers={"Authorization": f"Bearer {self.token}"},
        )
        self.assertEqual(cite.status_code, 200)
        self.assertEqual(cite.get_json()["citation"]["citation_id"], "c1")

        branch = self.client.post(
            "/api/chat/branch",
            json={
                "conversation_id": "conv_1",
                "parent_message_id": "a1",
                "parent_block_id": "b0",
                "mode": "build",
            },
            headers={"Authorization": f"Bearer {self.token}"},
        )
        self.assertEqual(branch.status_code, 200)
        self.assertEqual(branch.get_json()["branch_id"], "branch_1")


if __name__ == "__main__":
    unittest.main()
