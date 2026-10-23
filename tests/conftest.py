
import pytest
from argon2 import PasswordHasher

from app import create_app
from extension import db
from models import User, Document, DocumentGrant


@pytest.fixture
def app():
    test_app = create_app({
        "TESTING": True,
        "SECRET_KEY": "test-secret-key",
        "SQLALCHEMY_DATABASE_URI": "sqlite://",
        "WTF_CSRF_ENABLED": False,
    })

    with test_app.app_context():
        db.drop_all()
        db.create_all()

        hasher = PasswordHasher()
        owner = User(
            email="owner@example.com",
            password_hash=hasher.hash("Owner-test-password-123"),
            role="owner",
            is_active=True,
        )
        viewer = User(
            email="viewer@example.com",
            password_hash=hasher.hash("Viewer-test-password-123"),
            role="viewer",
            is_active=True,
        )
        other_user = User(
            email="other@example.com",
            password_hash=hasher.hash("Other-test-password-123"),
            role="viewer",
            is_active=True,
        )
        admin = User(
            email="admin@test.com",
            password_hash=hasher.hash("AdminPassword123!"),
            role="admin",
            is_active=True,
        )

        db.session.add_all([owner, viewer, other_user, admin])
        db.session.flush()

        document = Document(
            owner_id=owner.id,
            title="Test Document",
            category="General",
            storage_key="test-document.txt",
            content_hash="a" * 64,
        )
        db.session.add(document)
        db.session.flush()

        grant = DocumentGrant(
            document_id=document.id,
            user_id=viewer.id,
            permission="read",
            granted_by=owner.id,
        )
        db.session.add(grant)
        db.session.commit()

        test_app.config["TEST_DATA"] = {
            "owner_id": owner.id,
            "viewer_id": viewer.id,
            "other_id": other_user.id,
            "admin_id": admin.id,
            "document_id": document.id,
        }

    yield test_app

    with test_app.app_context():
        db.session.remove()
        db.drop_all()
