
import getpass
import os
import sys

# Allow this script to import app.py and models.py
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
    # Require explicit confirmation before creating accounts.
    confirmation = input(
        "This will create local TrustVault demo accounts. "
        "Continue? Type CREATE: "
    )

    if confirmation != "CREATE":
        print("Cancelled. No accounts created.")
        return

    admin_email = input("Demo admin email: ").strip().lower()
    admin_password = getpass.getpass("Demo admin password: ")

    viewer_email = input("Demo viewer email: ").strip().lower()
    viewer_password = getpass.getpass("Demo viewer password: ")

    if not all(
        [admin_email, admin_password, viewer_email, viewer_password]
    ):
        print("Error: Emails and passwords cannot be empty.")
        return

    if admin_email == viewer_email:
        print("Error: Admin and viewer must use different emails.")
        return

    if len(admin_password) < 12 or len(viewer_password) < 12:
        print("Error: Use passwords with at least 12 characters.")
        return

    app = create_app()

    with app.app_context():
        try:
            create_demo_user(admin_email, "admin", admin_password)
            create_demo_user(viewer_email, "viewer", viewer_password)
            db.session.commit()
            print("Demo account seeding completed.")
        except Exception:
            db.session.rollback()
            raise


if __name__ == "__main__":
    main()
