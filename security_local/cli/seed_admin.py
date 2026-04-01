import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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
