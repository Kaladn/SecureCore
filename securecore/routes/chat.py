"""Chat API for the SecureCore control center."""

from __future__ import annotations

from flask import Blueprint, current_app, jsonify, request
from flask_jwt_extended import jwt_required

from securecore.chat.models import MAX_MESSAGE_CHARS

chat_bp = Blueprint("chat", __name__)


@chat_bp.post("/api/chat/send")
@jwt_required()
def chat_send():
    executor = getattr(current_app, "chat_executor", None)
    if executor is None:
        return jsonify({"ok": False, "error": "chat executor unavailable"}), 503

    data = request.get_json(silent=True) or {}
    message = str(data.get("message", "")).strip()
    if not message:
        return jsonify({"ok": False, "error": "message required"}), 400
    if len(message) > MAX_MESSAGE_CHARS:
        return jsonify({"ok": False, "error": f"message exceeds {MAX_MESSAGE_CHARS} chars"}), 400

    try:
        result = executor.send(
            message=message,
            mode=data.get("mode"),
            conversation_id=data.get("conversation_id"),
            branch_id=data.get("branch_id"),
        )
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    return jsonify({"ok": True, **result})


@chat_bp.get("/api/chat/history")
@jwt_required()
def chat_history():
    executor = getattr(current_app, "chat_executor", None)
    if executor is None:
        return jsonify({"ok": False, "error": "chat executor unavailable"}), 503

    conversation_id = str(request.args.get("conversation_id", "")).strip()
    if not conversation_id:
        return jsonify({"ok": False, "error": "conversation_id required"}), 400

    branch_id = str(request.args.get("branch_id", "")).strip() or "main"
    try:
        result = executor.history(conversation_id=conversation_id, branch_id=branch_id)
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    return jsonify({"ok": True, **result})


@chat_bp.post("/api/chat/note")
@jwt_required()
def chat_note():
    executor = getattr(current_app, "chat_executor", None)
    if executor is None:
        return jsonify({"ok": False, "error": "chat executor unavailable"}), 503

    data = request.get_json(silent=True) or {}
    conversation_id = str(data.get("conversation_id", "")).strip()
    message_id = str(data.get("message_id", "")).strip()
    block_id = str(data.get("block_id", "")).strip()
    content = str(data.get("content", "")).strip()
    branch_id = str(data.get("branch_id", "")).strip() or None

    if not conversation_id or not message_id or not block_id or not content:
        return jsonify({"ok": False, "error": "conversation_id, message_id, block_id, and content required"}), 400

    try:
        result = executor.add_note(
            conversation_id=conversation_id,
            message_id=message_id,
            block_id=block_id,
            content=content,
            branch_id=branch_id,
        )
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    return jsonify({"ok": True, **result})


@chat_bp.post("/api/chat/cite")
@jwt_required()
def chat_cite():
    executor = getattr(current_app, "chat_executor", None)
    if executor is None:
        return jsonify({"ok": False, "error": "chat executor unavailable"}), 503

    data = request.get_json(silent=True) or {}
    conversation_id = str(data.get("conversation_id", "")).strip()
    message_id = str(data.get("message_id", "")).strip()
    block_id = str(data.get("block_id", "")).strip()
    source_type = str(data.get("source_type", "")).strip()
    source_ref = str(data.get("source_ref", "")).strip()
    excerpt = str(data.get("excerpt", "")).strip()
    branch_id = str(data.get("branch_id", "")).strip() or None

    if not conversation_id or not message_id or not block_id or not source_type or not source_ref:
        return jsonify({"ok": False, "error": "conversation_id, message_id, block_id, source_type, and source_ref required"}), 400

    try:
        result = executor.add_citation(
            conversation_id=conversation_id,
            message_id=message_id,
            block_id=block_id,
            source_type=source_type,
            source_ref=source_ref,
            excerpt=excerpt,
            branch_id=branch_id,
        )
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    return jsonify({"ok": True, **result})


@chat_bp.post("/api/chat/branch")
@jwt_required()
def chat_branch():
    executor = getattr(current_app, "chat_executor", None)
    if executor is None:
        return jsonify({"ok": False, "error": "chat executor unavailable"}), 503

    data = request.get_json(silent=True) or {}
    conversation_id = str(data.get("conversation_id", "")).strip()
    parent_message_id = str(data.get("parent_message_id", "")).strip()
    parent_block_id = str(data.get("parent_block_id", "")).strip()
    mode = data.get("mode")
    reason = str(data.get("reason", "")).strip() or "continue_chat"

    if not conversation_id or not parent_message_id:
        return jsonify({"ok": False, "error": "conversation_id and parent_message_id required"}), 400

    try:
        result = executor.continue_chat(
            conversation_id=conversation_id,
            parent_message_id=parent_message_id,
            parent_block_id=parent_block_id,
            mode=mode,
            reason=reason,
        )
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    return jsonify({"ok": True, **result})
