from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required
from core.auth import role_required
from core.db import db
from core.models import SecurityEvent


events_bp = Blueprint("events", __name__)


@events_bp.get("/api/events")
@jwt_required()
def list_events():
    rows = SecurityEvent.query.order_by(SecurityEvent.created_at.desc()).limit(200).all()
    return jsonify(
        {
            "ok": True,
            "items": [
                {
                    "id": row.id,
                    "event_type": row.event_type,
                    "severity": row.severity,
                    "source": row.source,
                    "details": row.details,
                    "created_at": row.created_at.isoformat(),
                }
                for row in rows
            ],
        }
    )


@events_bp.post("/api/events")
@jwt_required()
@role_required("admin")
def create_event():
    data = request.get_json(silent=True) or {}
    event_type = data.get("event_type", "manual")
    severity = data.get("severity", "info")
    source = data.get("source", "local")
    details = data.get("details", "")

    if not details:
        return jsonify({"ok": False, "error": "details required"}), 400

    row = SecurityEvent(
        event_type=event_type,
        severity=severity,
        source=source,
        details=details,
    )
    db.session.add(row)
    db.session.commit()

    return jsonify({"ok": True, "id": row.id}), 201
