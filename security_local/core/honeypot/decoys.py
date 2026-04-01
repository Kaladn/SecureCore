"""Decoy content generators.

These produce convincing fake responses that keep attackers engaged.
The content looks real enough that they keep probing - and every probe
feeds more evidence into their mirror cell.

All generated content is deterministic per-cell so repeated requests
return consistent fake data (attackers notice inconsistency).
"""

import hashlib
import json
import time
from datetime import datetime, UTC


def _seeded_hash(cell_id: str, salt: str) -> str:
    """Generate deterministic pseudo-random hex from cell_id + salt."""
    return hashlib.sha256(f"{cell_id}:{salt}".encode()).hexdigest()


def fake_admin_panel(cell_id: str) -> str:
    """Generate a convincing fake admin panel HTML page."""
    seed = _seeded_hash(cell_id, "admin-panel")
    fake_version = f"3.{int(seed[:2], 16) % 12}.{int(seed[2:4], 16) % 20}"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Administration Console</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
               margin: 0; background: #1a1a2e; color: #e0e0e0; }}
        .header {{ background: #16213e; padding: 12px 24px; border-bottom: 1px solid #0f3460;
                   display: flex; justify-content: space-between; align-items: center; }}
        .header h1 {{ margin: 0; font-size: 18px; color: #e94560; }}
        .version {{ font-size: 11px; color: #666; }}
        .container {{ padding: 24px; max-width: 1200px; margin: 0 auto; }}
        .login-box {{ background: #16213e; border: 1px solid #0f3460; border-radius: 8px;
                      padding: 32px; max-width: 400px; margin: 80px auto; }}
        .login-box h2 {{ margin-top: 0; color: #e94560; }}
        input {{ width: 100%; padding: 10px; margin: 8px 0; background: #1a1a2e;
                border: 1px solid #0f3460; color: #e0e0e0; border-radius: 4px; box-sizing: border-box; }}
        button {{ width: 100%; padding: 10px; background: #e94560; color: white;
                 border: none; border-radius: 4px; cursor: pointer; font-size: 14px; }}
        .status {{ font-size: 12px; color: #4ecca3; margin-top: 16px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>SecureCore Admin</h1>
        <span class="version">v{fake_version}</span>
    </div>
    <div class="container">
        <div class="login-box">
            <h2>Administrator Login</h2>
            <form method="POST" action="/admin/authenticate">
                <input type="text" name="username" placeholder="Admin Username" autocomplete="off">
                <input type="password" name="password" placeholder="Password" autocomplete="off">
                <input type="hidden" name="csrf_token" value="{seed[:32]}">
                <button type="submit">Sign In</button>
            </form>
            <div class="status">System Status: Online | Uptime: {int(seed[:3], 16) % 720}h</div>
        </div>
    </div>
</body>
</html>"""


def fake_api_keys_response(cell_id: str) -> dict:
    """Generate fake API keys that look real and tempting."""
    seed = _seeded_hash(cell_id, "api-keys")
    seed2 = _seeded_hash(cell_id, "api-keys-2")

    return {
        "status": "ok",
        "keys": [
            {
                "name": "production-primary",
                "key": f"sk_live_{seed[:40]}",
                "created": "2025-11-03T08:14:22Z",
                "last_used": "2026-03-31T22:41:07Z",
                "permissions": ["read", "write", "admin"],
                "rate_limit": 10000,
            },
            {
                "name": "staging-deploy",
                "key": f"sk_test_{seed2[:40]}",
                "created": "2026-01-15T14:30:00Z",
                "last_used": "2026-03-30T11:22:33Z",
                "permissions": ["read", "write"],
                "rate_limit": 5000,
            },
            {
                "name": "backup-service",
                "key": f"sk_backup_{seed[10:50]}",
                "created": "2025-09-20T06:00:00Z",
                "last_used": "2026-03-28T03:00:00Z",
                "permissions": ["read", "backup"],
                "rate_limit": 1000,
            },
        ],
        "warning": "Do not share these keys. Rotation scheduled: 2026-04-15",
    }


def fake_user_database(cell_id: str) -> dict:
    """Generate a convincing fake user database dump."""
    seed = _seeded_hash(cell_id, "userdb")
    fake_users = []
    departments = ["Engineering", "Security", "Operations", "Finance", "Executive"]
    roles = ["user", "admin", "superadmin", "readonly", "operator"]

    for i in range(15):
        user_seed = _seeded_hash(cell_id, f"user-{i}")
        dept_idx = int(user_seed[:2], 16) % len(departments)
        role_idx = int(user_seed[2:4], 16) % len(roles)
        fake_users.append({
            "id": i + 1,
            "username": f"user_{user_seed[:6]}",
            "email": f"{user_seed[:8]}@internal.securecore.local",
            "role": roles[role_idx],
            "department": departments[dept_idx],
            "password_hash": f"$2b$12${user_seed[:53]}",
            "last_login": f"2026-03-{(int(user_seed[4:6], 16) % 28) + 1:02d}T{int(user_seed[6:8], 16) % 24:02d}:00:00Z",
            "mfa_enabled": int(user_seed[8:10], 16) % 3 != 0,
            "active": True,
        })

    return {
        "table": "users",
        "record_count": len(fake_users),
        "exported_at": datetime.now(UTC).isoformat(),
        "records": fake_users,
    }


def fake_config_dump(cell_id: str) -> dict:
    """Generate a convincing fake configuration dump."""
    seed = _seeded_hash(cell_id, "config")

    return {
        "application": {
            "name": "SecureCore Platform",
            "version": f"2.{int(seed[:2], 16) % 8}.{int(seed[2:4], 16) % 15}",
            "environment": "production",
            "debug": False,
        },
        "database": {
            "host": "db-primary.internal.securecore.local",
            "port": 5432,
            "name": "securecore_prod",
            "username": "sc_app_user",
            "password": f"pg_{seed[:24]}",
            "ssl_mode": "verify-full",
            "pool_size": 20,
            "replica_host": "db-replica.internal.securecore.local",
        },
        "redis": {
            "host": "cache.internal.securecore.local",
            "port": 6379,
            "password": f"redis_{seed[24:48]}",
            "db": 0,
        },
        "aws": {
            "access_key_id": f"AKIA{seed[:16].upper()}",
            "secret_access_key": f"{seed[16:56]}",
            "region": "us-east-1",
            "s3_bucket": "securecore-prod-assets",
        },
        "smtp": {
            "host": "smtp.internal.securecore.local",
            "port": 587,
            "username": "alerts@securecore.local",
            "password": f"smtp_{seed[8:32]}",
        },
        "jwt": {
            "secret": f"jwt_{seed[32:]}",
            "algorithm": "HS256",
            "expiry_hours": 24,
        },
    }


def fake_server_status(cell_id: str) -> dict:
    """Generate fake server status information."""
    seed = _seeded_hash(cell_id, "status")

    return {
        "hostname": "prod-web-01.securecore.local",
        "os": "Ubuntu 22.04.3 LTS",
        "kernel": "5.15.0-91-generic",
        "uptime_hours": int(seed[:4], 16) % 8760,
        "load_average": [
            round(int(seed[4:6], 16) / 100, 2),
            round(int(seed[6:8], 16) / 100, 2),
            round(int(seed[8:10], 16) / 100, 2),
        ],
        "memory": {
            "total_gb": 64,
            "used_gb": round(32 + (int(seed[10:12], 16) % 20), 1),
            "free_gb": round(32 - (int(seed[10:12], 16) % 20), 1),
        },
        "disk": {
            "total_gb": 500,
            "used_gb": round(200 + (int(seed[12:14], 16) % 150), 1),
            "mount": "/",
        },
        "services": {
            "nginx": "running",
            "postgresql": "running",
            "redis": "running",
            "celery": "running",
            "gunicorn": "running",
        },
        "network": {
            "interfaces": ["eth0", "lo"],
            "listening_ports": [22, 80, 443, 5432, 6379, 8000],
            "firewall": "active",
        },
        "last_deploy": f"2026-03-{(int(seed[14:16], 16) % 28) + 1:02d}T10:30:00Z",
        "ssl_cert_expiry": "2026-09-15T00:00:00Z",
    }


def fake_backup_listing(cell_id: str) -> dict:
    """Generate fake backup file listing."""
    seed = _seeded_hash(cell_id, "backups")
    backups = []

    for i in range(8):
        b_seed = _seeded_hash(cell_id, f"backup-{i}")
        day = (int(b_seed[:2], 16) % 28) + 1
        size_mb = 500 + (int(b_seed[2:6], 16) % 4500)
        backups.append({
            "filename": f"securecore_prod_2026-03-{day:02d}_{b_seed[:8]}.sql.gz.enc",
            "size_mb": size_mb,
            "checksum": f"sha256:{b_seed[:64]}",
            "encrypted": True,
            "created": f"2026-03-{day:02d}T02:00:00Z",
            "retention_days": 90,
        })

    return {
        "backup_location": "/mnt/backup/securecore/",
        "encryption": "AES-256-GCM",
        "total_backups": len(backups),
        "backups": sorted(backups, key=lambda b: b["created"], reverse=True),
    }


def fake_internal_network_map(cell_id: str) -> dict:
    """Generate a convincing internal network topology."""
    seed = _seeded_hash(cell_id, "netmap")

    return {
        "network": "10.0.0.0/16",
        "vlan_count": 8,
        "hosts": [
            {"ip": "10.0.1.10", "hostname": "prod-web-01", "role": "web-server", "os": "Ubuntu 22.04"},
            {"ip": "10.0.1.11", "hostname": "prod-web-02", "role": "web-server", "os": "Ubuntu 22.04"},
            {"ip": "10.0.2.10", "hostname": "db-primary", "role": "database", "os": "Ubuntu 22.04", "port": 5432},
            {"ip": "10.0.2.11", "hostname": "db-replica", "role": "database-replica", "os": "Ubuntu 22.04", "port": 5432},
            {"ip": "10.0.3.10", "hostname": "cache-01", "role": "redis", "os": "Ubuntu 22.04", "port": 6379},
            {"ip": "10.0.4.10", "hostname": "monitor-01", "role": "monitoring", "os": "Ubuntu 22.04"},
            {"ip": "10.0.5.10", "hostname": "vpn-gateway", "role": "vpn", "os": "pfSense"},
            {"ip": "10.0.6.10", "hostname": "ci-runner-01", "role": "ci-cd", "os": "Ubuntu 22.04"},
            {"ip": "10.0.7.10", "hostname": "log-aggregator", "role": "logging", "os": "Ubuntu 22.04"},
            {"ip": "10.0.8.10", "hostname": "bastion-01", "role": "bastion", "os": "Ubuntu 22.04", "port": 22},
        ],
        "gateway": "10.0.0.1",
        "dns_servers": ["10.0.0.2", "10.0.0.3"],
        "domain": "securecore.local",
    }


def fake_login_success(cell_id: str, username: str) -> dict:
    """Generate a fake successful login response with a useless token."""
    seed = _seeded_hash(cell_id, f"token-{username}")
    return {
        "status": "authenticated",
        "user": username,
        "role": "admin",
        "token": f"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.{seed[:43]}.{seed[20:48]}",
        "expires_in": 86400,
        "permissions": ["read", "write", "admin", "deploy", "audit"],
    }


def fake_error_with_stack(cell_id: str, path: str) -> dict:
    """Generate a fake error response that leaks stack trace info.

    Attackers love stack traces - they reveal framework versions,
    file paths, and internal structure. These are all fake.
    """
    seed = _seeded_hash(cell_id, f"error-{path}")
    return {
        "error": "InternalServerError",
        "message": "Unhandled exception in request handler",
        "status": 500,
        "traceback": [
            f"  File \"/opt/securecore/app/server.py\", line {int(seed[:3], 16) % 500}, in handle_request",
            f"    result = await dispatch(request, route_map[path])",
            f"  File \"/opt/securecore/app/dispatch.py\", line {int(seed[3:6], 16) % 300}, in dispatch",
            f"    return handler.execute(validated_params)",
            f"  File \"/opt/securecore/app/handlers/{seed[:8]}.py\", line {int(seed[6:9], 16) % 200}, in execute",
            f"    row = db.session.query(Model).filter_by(id=params['id']).one()",
            f"  sqlalchemy.exc.NoResultFound: No row found for query",
        ],
        "request_id": seed[:16],
        "server": "gunicorn/21.2.0",
        "python_version": "3.11.7",
    }


DECOY_REGISTRY = {
    "admin_panel": fake_admin_panel,
    "api_keys": fake_api_keys_response,
    "user_database": fake_user_database,
    "config_dump": fake_config_dump,
    "server_status": fake_server_status,
    "backup_listing": fake_backup_listing,
    "network_map": fake_internal_network_map,
}
