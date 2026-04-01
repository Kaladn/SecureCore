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


class MirrorCellRecord(db.Model):
    """Persistent record of an attacker mirror cell session."""
    __tablename__ = "mirror_cells"

    id = db.Column(db.Integer, primary_key=True)
    cell_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    attacker_fingerprint = db.Column(db.String(128), nullable=False, index=True)
    source_ip = db.Column(db.String(45), nullable=False)
    first_seen = db.Column(db.DateTime, default=lambda: datetime.now(UTC), nullable=False)
    last_seen = db.Column(db.DateTime, default=lambda: datetime.now(UTC), nullable=False)
    escalation_level = db.Column(db.Integer, default=0, nullable=False)
    total_interactions = db.Column(db.Integer, default=0, nullable=False)
    locked = db.Column(db.Boolean, default=False, nullable=False)
    status = db.Column(db.String(20), default="tracking", nullable=False)


class ForensicEvidence(db.Model):
    """Tamper-evident forensic evidence chain for a mirror cell."""
    __tablename__ = "forensic_evidence"

    id = db.Column(db.Integer, primary_key=True)
    cell_id = db.Column(db.String(64), db.ForeignKey("mirror_cells.cell_id"), nullable=False, index=True)
    sequence = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(UTC), nullable=False)
    evidence_type = db.Column(db.String(50), nullable=False)
    method = db.Column(db.String(10), nullable=False)
    path = db.Column(db.String(500), nullable=False)
    headers_hash = db.Column(db.String(64), nullable=False)
    body_hash = db.Column(db.String(64), nullable=False)
    source_ip = db.Column(db.String(45), nullable=False)
    source_port = db.Column(db.Integer, nullable=True)
    user_agent = db.Column(db.String(500), nullable=False, default="")
    tool_signature = db.Column(db.String(100), nullable=False, default="unknown")
    raw_headers = db.Column(db.Text, nullable=False)
    raw_body = db.Column(db.Text, nullable=False, default="")
    response_served = db.Column(db.Text, nullable=False, default="")
    chain_hash = db.Column(db.String(64), nullable=False)
    previous_hash = db.Column(db.String(64), nullable=False, default="GENESIS")

    __table_args__ = (
        db.UniqueConstraint("cell_id", "sequence", name="uq_cell_sequence"),
    )
