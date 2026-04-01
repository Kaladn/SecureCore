from flask import Flask
from core.config import load_settings, validate_settings
from core.db import db
from core.auth import jwt
from core.logging_setup import configure_logging
from core.routes.health import health_bp
from core.routes.auth import auth_bp
from core.routes.events import events_bp
from core.routes.honeypot_admin import honeypot_admin_bp


def create_app() -> Flask:
    settings = load_settings()
    validate_settings(settings)
    configure_logging()

    app = Flask(__name__)
    app.config.update(settings)

    db.init_app(app)
    jwt.init_app(app)

    # Real routes
    app.register_blueprint(health_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(events_bp)
    app.register_blueprint(honeypot_admin_bp)

    # Honeypot trap routes
    if app.config.get("HONEYPOT_ENABLED", True):
        from core.honeypot.trap_routes import trap_bp
        app.register_blueprint(trap_bp)

    with app.app_context():
        from core import models  # noqa: F401
        db.create_all()

    return app


app = create_app()


if __name__ == "__main__":
    host = app.config["BIND_HOST"]
    port = int(app.config["BIND_PORT"])
    app.run(host=host, port=port, debug=False)
