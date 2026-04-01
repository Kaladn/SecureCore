"""Decoy content generators.

Produces convincing fake responses. All generated content is deterministic
per-cell so repeated requests return consistent fake data.
"""

import hashlib
from datetime import datetime, UTC


def _seeded_hash(cell_id: str, salt: str) -> str:
    return hashlib.sha256(f"{cell_id}:{salt}".encode()).hexdigest()


def fake_admin_panel(cell_id: str) -> str:
    seed = _seeded_hash(cell_id, "admin-panel")
    ver = f"3.{int(seed[:2], 16) % 12}.{int(seed[2:4], 16) % 20}"
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Administration Console</title>
<style>
body{{font-family:-apple-system,sans-serif;margin:0;background:#1a1a2e;color:#e0e0e0}}
.header{{background:#16213e;padding:12px 24px;border-bottom:1px solid #0f3460;display:flex;justify-content:space-between}}
.header h1{{margin:0;font-size:18px;color:#e94560}}.version{{font-size:11px;color:#666}}
.login-box{{background:#16213e;border:1px solid #0f3460;border-radius:8px;padding:32px;max-width:400px;margin:80px auto}}
.login-box h2{{margin-top:0;color:#e94560}}
input{{width:100%;padding:10px;margin:8px 0;background:#1a1a2e;border:1px solid #0f3460;color:#e0e0e0;border-radius:4px;box-sizing:border-box}}
button{{width:100%;padding:10px;background:#e94560;color:white;border:none;border-radius:4px;cursor:pointer}}
.status{{font-size:12px;color:#4ecca3;margin-top:16px}}
</style></head><body>
<div class="header"><h1>SecureCore Admin</h1><span class="version">v{ver}</span></div>
<div style="padding:24px;max-width:1200px;margin:0 auto">
<div class="login-box"><h2>Administrator Login</h2>
<form method="POST" action="/admin/authenticate">
<input type="text" name="username" placeholder="Admin Username" autocomplete="off">
<input type="password" name="password" placeholder="Password" autocomplete="off">
<input type="hidden" name="csrf_token" value="{seed[:32]}">
<button type="submit">Sign In</button></form>
<div class="status">System Status: Online | Uptime: {int(seed[:3], 16) % 720}h</div>
</div></div></body></html>"""


def fake_api_keys(cell_id: str) -> dict:
    s = _seeded_hash(cell_id, "api-keys")
    s2 = _seeded_hash(cell_id, "api-keys-2")
    return {"status": "ok", "keys": [
        {"name": "production-primary", "key": f"sk_live_{s[:40]}", "permissions": ["read", "write", "admin"]},
        {"name": "staging-deploy", "key": f"sk_test_{s2[:40]}", "permissions": ["read", "write"]},
        {"name": "backup-service", "key": f"sk_backup_{s[10:50]}", "permissions": ["read", "backup"]},
    ], "warning": "Do not share. Rotation scheduled: 2026-04-15"}


def fake_user_database(cell_id: str) -> dict:
    seed = _seeded_hash(cell_id, "userdb")
    depts = ["Engineering", "Security", "Operations", "Finance", "Executive"]
    roles = ["user", "admin", "superadmin", "readonly", "operator"]
    users = []
    for i in range(15):
        us = _seeded_hash(cell_id, f"user-{i}")
        users.append({
            "id": i+1, "username": f"user_{us[:6]}",
            "email": f"{us[:8]}@internal.securecore.local",
            "role": roles[int(us[2:4], 16) % len(roles)],
            "department": depts[int(us[:2], 16) % len(depts)],
            "password_hash": f"$2b$12${us[:53]}",
            "mfa_enabled": int(us[8:10], 16) % 3 != 0, "active": True,
        })
    return {"table": "users", "record_count": len(users), "records": users}


def fake_config_dump(cell_id: str) -> dict:
    s = _seeded_hash(cell_id, "config")
    return {
        "database": {"host": "db-primary.internal.securecore.local", "port": 5432,
                      "username": "sc_app_user", "password": f"pg_{s[:24]}"},
        "redis": {"host": "cache.internal.securecore.local", "password": f"redis_{s[24:48]}"},
        "aws": {"access_key_id": f"AKIA{s[:16].upper()}", "secret_access_key": s[16:56]},
        "jwt": {"secret": f"jwt_{s[32:]}", "algorithm": "HS256"},
    }


def fake_server_status(cell_id: str) -> dict:
    s = _seeded_hash(cell_id, "status")
    return {
        "hostname": "prod-web-01.securecore.local", "os": "Ubuntu 22.04.3 LTS",
        "uptime_hours": int(s[:4], 16) % 8760,
        "services": {"nginx": "running", "postgresql": "running", "redis": "running", "gunicorn": "running"},
        "network": {"interfaces": ["eth0", "lo"], "listening_ports": [22, 80, 443, 5432, 6379, 8000]},
    }


def fake_network_map(cell_id: str) -> dict:
    return {
        "network": "10.0.0.0/16", "hosts": [
            {"ip": "10.0.1.10", "hostname": "prod-web-01", "role": "web-server"},
            {"ip": "10.0.2.10", "hostname": "db-primary", "role": "database", "port": 5432},
            {"ip": "10.0.2.11", "hostname": "db-replica", "role": "database-replica"},
            {"ip": "10.0.3.10", "hostname": "cache-01", "role": "redis"},
            {"ip": "10.0.5.10", "hostname": "vpn-gateway", "role": "vpn"},
            {"ip": "10.0.8.10", "hostname": "bastion-01", "role": "bastion", "port": 22},
        ], "gateway": "10.0.0.1", "domain": "securecore.local",
    }


def fake_backup_listing(cell_id: str) -> dict:
    s = _seeded_hash(cell_id, "backups")
    backups = []
    for i in range(8):
        bs = _seeded_hash(cell_id, f"backup-{i}")
        backups.append({
            "filename": f"securecore_prod_2026-03-{(int(bs[:2],16)%28)+1:02d}_{bs[:8]}.sql.gz.enc",
            "size_mb": 500 + (int(bs[2:6], 16) % 4500), "encrypted": True,
            "checksum": f"sha256:{bs[:64]}",
        })
    return {"backup_location": "/mnt/backup/securecore/", "encryption": "AES-256-GCM", "backups": backups}


def fake_login_success(cell_id: str, username: str) -> dict:
    s = _seeded_hash(cell_id, f"token-{username}")
    return {
        "status": "authenticated", "user": username, "role": "admin",
        "token": f"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.{s[:43]}.{s[20:48]}",
        "permissions": ["read", "write", "admin", "deploy", "audit"],
    }


def fake_error_with_stack(cell_id: str, path: str) -> dict:
    s = _seeded_hash(cell_id, f"error-{path}")
    return {
        "error": "InternalServerError", "status": 500,
        "traceback": [
            f'  File "/opt/securecore/app/server.py", line {int(s[:3],16)%500}, in handle_request',
            f'  File "/opt/securecore/app/dispatch.py", line {int(s[3:6],16)%300}, in dispatch',
            f"  sqlalchemy.exc.NoResultFound: No row found for query",
        ], "server": "gunicorn/21.2.0", "python_version": "3.11.7",
    }


def fake_env_file(cell_id: str) -> str:
    return (
        f"# Production Environment\n"
        f"SECRET_KEY=sk_{cell_id}a1b2c3d4e5f6\n"
        f"DATABASE_URL=postgresql://app:pg_{cell_id}@db-primary:5432/prod\n"
        f"AWS_ACCESS_KEY_ID=AKIA{cell_id.upper()[:16]}\n"
        f"AWS_SECRET_ACCESS_KEY={cell_id}secretkey1234567890\n"
        f"JWT_SECRET={cell_id}_jwt_secret_key\n"
    )


def fake_git_config() -> str:
    return (
        "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n"
        '[remote "origin"]\n\turl = git@github.com:securecore-internal/platform.git\n'
        "\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
        '[user]\n\tname = deploy-bot\n\temail = deploy@securecore.local\n'
    )
