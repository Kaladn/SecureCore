from flask import Blueprint, jsonify, request
from flask_jwt_extended import create_access_token
from core.models import User


auth_bp = Blueprint("auth", __name__)


@auth_bp.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"ok": False, "error": "missing credentials"}), 400

    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        return jsonify({"ok": False, "error": "invalid credentials"}), 401

    token = create_access_token(identity=str(user.id), additional_claims={"role": user.role.name})
    return jsonify({"ok": True, "access_token": token})
