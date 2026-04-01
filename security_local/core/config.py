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
        "HONEYPOT_ENABLED": os.getenv("HONEYPOT_ENABLED", "true").lower() == "true",
        "HONEYPOT_ESCALATION_THRESHOLD": int(os.getenv("HONEYPOT_ESCALATION_THRESHOLD", "3")),
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
