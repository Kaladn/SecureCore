import os
from dotenv import load_dotenv


REQUIRED_KEYS = ["SECRET_KEY", "JWT_SECRET_KEY", "BIND_HOST", "BIND_PORT"]


def load_settings() -> dict:
    load_dotenv()
    return {
        "SECRET_KEY": os.getenv("SECRET_KEY", ""),
        "JWT_SECRET_KEY": os.getenv("JWT_SECRET_KEY", ""),
        "SQLALCHEMY_DATABASE_URI": os.getenv("DATABASE_URL", "sqlite:///securecore.db"),
        "SQLALCHEMY_TRACK_MODIFICATIONS": False,
        "BIND_HOST": os.getenv("BIND_HOST", "127.0.0.1"),
        "BIND_PORT": os.getenv("BIND_PORT", "5057"),
        "HONEYPOT_ENABLED": os.getenv("HONEYPOT_ENABLED", "true").lower() == "true",
        "HONEYPOT_ESCALATION_THRESHOLD": int(os.getenv("HONEYPOT_ESCALATION_THRESHOLD", "3")),
        "DATA_DIR": os.getenv("DATA_DIR", "data"),
        "LOG_DIR": os.getenv("LOG_DIR", "logs"),
    }


def validate_settings(settings: dict) -> None:
    missing = [k for k in REQUIRED_KEYS if not settings.get(k)]
    if missing:
        raise RuntimeError(f"Missing required settings: {', '.join(missing)}")
    if settings["BIND_HOST"] != "127.0.0.1":
        raise RuntimeError("Refusing to start: BIND_HOST must be 127.0.0.1 for local-safe mode")
    try:
        int(settings["BIND_PORT"])
    except ValueError as exc:
        raise RuntimeError("BIND_PORT must be an integer") from exc
