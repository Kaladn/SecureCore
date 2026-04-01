from functools import wraps
from flask import jsonify
from flask_jwt_extended import JWTManager, get_jwt, verify_jwt_in_request


jwt = JWTManager()


def role_required(required_role: str):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt()
            if claims.get("role") != required_role:
                return jsonify({"ok": False, "error": "forbidden"}), 403
            return fn(*args, **kwargs)

        return wrapper

    return decorator
