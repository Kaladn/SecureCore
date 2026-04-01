# Security Local Bootstrap

## Mission

Build a **Python-only, localhost-only, no-npm** local security platform that starts small and stays hard.

This first cut is intentionally narrow:

* local config validation
* local auth + RBAC skeleton
* append-only-ish security events
* localhost API only
* zero external feeds enabled by default
* zero training routes
* zero scraping/runtime web search

## Ground rules

* **No npm installs. Ever.**
* No React, Vite, webpack, axios, or browser package chain.
* UI will be Flask + Jinja + vanilla JS later.
* Runtime binds to `127.0.0.1` only.
* External connectors are disabled until explicitly wired.
* Maintenance actions happen through CLI, not public routes.

## Folder tree

```text
security_local/
  app.py
  requirements.txt
  .env.example
  core/
    __init__.py
    config.py
    db.py
    auth.py
    models.py
    logging_setup.py
    routes/
      __init__.py
      health.py
      auth.py
      events.py
  cli/
    seed_admin.py
  templates/
    base.html
    login.html
  static/
    app.js
```

## requirements.txt

```txt
Flask==3.1.0
Flask-SQLAlchemy==3.1.1
Flask-JWT-Extended==4.7.1
Werkzeug==3.1.3
python-dotenv==1.0.1
cryptography==44.0.2
```

## .env.example

```env
SECRET_KEY=change-me
JWT_SECRET_KEY=change-me-too
DATABASE_URL=sqlite:///security_local.db
BIND_HOST=127.0.0.1
BIND_PORT=5057
CONFIG_ENCRYPTION_KEY=
SECURITY_LOCAL_ADMIN_USER=admin
SECURITY_LOCAL_ADMIN_PASS=change-this-now
```

## app.py

```python
from flask import Flask
from core.config import load_settings, validate_settings
from core.db import db
from core.logging_setup import configure_logging
from core.routes.health import health_bp
from core.routes.auth import auth_bp
from core.routes.events import events_bp


def create_app() -> Flask:
    settings = load_settings()
    validate_settings(settings)
    configure_logging()

    app = Flask(__name__)
    app.config.update(settings)

    db.init_app(app)

    app.register_blueprint(health_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(events_bp)

    with app.app_context():
        from core import models  # noqa: F401
        db.create_all()

    return app


app = create_app()


if __name__ == "__main__":
    host = app.config["BIND_HOST"]
    port = int(app.config["BIND_PORT"])
    app.run(host=host, port=port, debug=False)
```

## core/**init**.py

```python
# security_local core package
```

## core/config.py

```python
import os
from dotenv import load_dotenv


REQUIRED_KEYS = [
    "SECRET_KEY",
    "JWT_SECRET_KEY",
    "DATABASE_URL",
    "BIND_HOST",
    "BIND_PORT",
]


def load_settings() -> dict:
    load_dotenv()
    return {
        "SECRET_KEY": os.getenv("SECRET_KEY", ""),
        "JWT_SECRET_KEY": os.getenv("JWT_SECRET_KEY", ""),
        "SQLALCHEMY_DATABASE_URI": os.getenv("DATABASE_URL", "sqlite:///security_local.db"),
        "SQLALCHEMY_TRACK_MODIFICATIONS": False,
        "BIND_HOST": os.getenv("BIND_HOST", "127.0.0.1"),
        "BIND_PORT": os.getenv("BIND_PORT", "5057"),
    }


def validate_settings(settings: dict) -> None:
    missing = [key for key in REQUIRED_KEYS if not settings.get(key) and key != "DATABASE_URL"]
    if missing:
        raise RuntimeError(f"Missing required settings: {', '.join(missing)}")

    if settings["BIND_HOST"] != "127.0.0.1":
        raise RuntimeError("Refusing to start: BIND_HOST must be 127.0.0.1 for local-safe mode")

    try:
        int(settings["BIND_PORT"])
    except ValueError as exc:
        raise RuntimeError("BIND_PORT must be an integer") from exc
```

## core/db.py

```python
from flask_sqlalchemy import SQLAlchemy


db = SQLAlchemy()
```

## core/logging_setup.py

```python
import logging


def configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s :: %(message)s",
    )
```

## core/models.py

```python
from datetime import datetime, UTC
from werkzeug.security import generate_password_hash, check_password_hash
from core.db import db


class Role(db.Model):
    __tablename__ = "roles"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey("roles.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC), nullable=False)

    role = db.relationship("Role", backref=db.backref("users", lazy=True))

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class SecurityEvent(db.Model):
    __tablename__ = "security_events"

    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(100), nullable=False, index=True)
    severity = db.Column(db.String(20), nullable=False, default="info")
    source = db.Column(db.String(100), nullable=False, default="local")
    details = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC), nullable=False, index=True)
```

## core/auth.py

```python
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
```

## core/routes/**init**.py

```python
# route package
```

## core/routes/health.py

```python
from flask import Blueprint, jsonify


health_bp = Blueprint("health", __name__)


@health_bp.get("/api/health")
def health():
    return jsonify({"ok": True, "mode": "local-safe", "npm": "forbidden"})
```

## core/routes/auth.py

```python
from flask import Blueprint, jsonify, request
from flask_jwt_extended import create_access_token
from core.db import db
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
```

## core/routes/events.py

```python
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
```

## cli/seed_admin.py

```python
import os
from app import app
from core.db import db
from core.models import Role, User


def main() -> None:
    username = os.getenv("SECURITY_LOCAL_ADMIN_USER", "admin")
    password = os.getenv("SECURITY_LOCAL_ADMIN_PASS", "change-this-now")

    with app.app_context():
        admin_role = Role.query.filter_by(name="admin").first()
        if not admin_role:
            admin_role = Role(name="admin")
            db.session.add(admin_role)
            db.session.commit()

        user = User.query.filter_by(username=username).first()
        if not user:
            user = User(username=username, role_id=admin_role.id)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            print(f"Created admin user: {username}")
        else:
            print(f"Admin user already exists: {username}")


if __name__ == "__main__":
    main()
```

## templates/base.html

```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Security Local</title>
  </head>
  <body>
    {% block body %}{% endblock %}
  </body>
</html>
```

## templates/login.html

```html
{% extends "base.html" %}
{% block body %}
<h1>Security Local</h1>
<p>Login page stub.</p>
{% endblock %}
```

## static/app.js

```javascript
console.log("Security Local vanilla JS stub loaded.");
```

## First run

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
python cli/seed_admin.py
python app.py
```

## Immediate next steps

1. initialize `Flask-JWT-Extended` properly inside app creation
2. add a localhost-only session guard test
3. add a Windows collector module for listeners / Defender / firewall state
4. move from `db.create_all()` to Alembic migrations
5. add a read-only dashboard page with vanilla JS

## Codex handoff prompt

```text
Take this Python-only localhost-only bootstrap and continue Phase 1 only.
Do not introduce npm, Node, React, Vite, webpack, axios, or any browser package manager.
Keep runtime bound to 127.0.0.1.
Next tasks:
- wire Flask-JWT-Extended initialization cleanly
- add a /api/me route
- add a Windows collector module that reads listeners and Defender state without changing system state
- add tests for config validation and auth login failure paths
- keep all changes small and file-scoped
```
