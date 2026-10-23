
import getpass
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from argon2 import PasswordHasher
from app import create_app
from extension import db
from models import User

password_hasher = PasswordHasher()


def create_demo_user(email, role, password):
    email = email.strip().lower()

    existing_user = db.session.execute(
        db.select(User).where(User.email == email)
    ).scalar_one_or_none()

    if existing_user:
        print(f"Account already exists: {email} (not changed)")
        return

    user = User(
        email=email,
        password_hash=password_hasher.hash(password),
        role=role,
        is_active=True,
    )
    db.session.add(user)
    print(f"Prepared {role} account: {email}")


def main():
    confirmation = input(
        "Create local TrustVault demo accounts? Type CREATE: "
    )
    if confirmation != "CREATE":
        print("Cancelled. No accounts created.")
        return

    accounts = [
        ("admin", input("Admin email: ").strip().lower(),
         getpass.getpass("Admin password: ")),
        ("owner", input("Owner email: ").strip().lower(),
         getpass.getpass("Owner password: ")),
        ("viewer", input("Viewer email: ").strip().lower(),
         getpass.getpass("Viewer password: ")),
    ]

    emails = [email for _, email, _ in accounts]

    if any(not email or not password for _, email, password in accounts):
        print("Error: Emails and passwords cannot be empty.")
        return

    if len(set(emails)) != len(emails):
        print("Error: Each demo account must have a different email.")
        return

    if any(len(password) < 12 for _, _, password in accounts):
        print("Error: Each password must be at least 12 characters.")
        return

    app = create_app()

    with app.app_context():
        try:
            for role, email, password in accounts:
                create_demo_user(email, role, password)

            db.session.commit()
            print("Demo account seeding completed.")
        except Exception:
            db.session.rollback()
            raise


if __name__ == "__main__":
    main()