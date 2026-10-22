
import pytest
from flask_login import login_user, logout_user
from argon2 import PasswordHasher

from app import create_app
from extension import db
from models import User, Document, DocumentGrant
from permissions import can_access_document


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

        db.session.add_all([
            owner,
            viewer,
            other_user,
            admin,
        ])
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

        db.session.remove()
        db.drop_all()


def check_access(app, user_id, document_id, permission="read"):
    with app.app_context():
        user = db.session.get(User, user_id)
        document = db.session.get(Document, document_id)

        with app.test_request_context("/"):
            login_user(user)

            try:
                return can_access_document(
                    user, document, permission
                )
            finally:
                logout_user()


def test_owner_can_read_and_edit(app):
    data = app.config["TEST_DATA"]

    assert check_access(
        app, data["owner_id"], data["document_id"], "read"
    ) is True

    assert check_access(
        app, data["owner_id"], data["document_id"], "edit"
    ) is True


def test_viewer_with_read_grant_can_read_but_not_edit(app):
    data = app.config["TEST_DATA"]

    assert check_access(
        app, data["viewer_id"], data["document_id"], "read"
    ) is True

    assert check_access(
        app, data["viewer_id"], data["document_id"], "edit"
    ) is False


def test_user_without_grant_is_denied(app):
    data = app.config["TEST_DATA"]

    assert check_access(
        app, data["other_id"], data["document_id"], "read"
    ) is False

    assert check_access(
        app, data["other_id"], data["document_id"], "edit"
    ) is False


def test_admin_can_access_document(app):
    data = app.config["TEST_DATA"]

    assert check_access(
        app, data["admin_id"], data["document_id"], "read"
    ) is True

    assert check_access(
        app, data["admin_id"], data["document_id"], "edit"
    ) is True


def test_deleted_document_is_denied(app):
    data = app.config["TEST_DATA"]

    with app.app_context():
        document = db.session.get(
            Document, data["document_id"]
        )
        document.is_deleted = True
        db.session.commit()

    assert check_access(
        app, data["owner_id"], data["document_id"], "read"
    ) is False


def test_invalid_permission_is_denied(app):
    data = app.config["TEST_DATA"]

    assert check_access(
        app, data["owner_id"], data["document_id"], "delete"
    )is False
    
from models import DocumentGrant


def can_access_document(user, document, action):
    # Reject missing or inactive users
    if user is None or not user.is_active:
        return False

    # Only support read and edit actions
    if action not in ("read", "edit"):
        return False

    # Reject missing or deleted documents
    if document is None or document.is_deleted:
        return False

    # Admins can read and edit active documents
    if user.role == "admin":
        return True

    # Owners can read and edit their own documents
    if document.owner_id == user.id:
        return True

    # Other users need an explicit permission grant
    grant = DocumentGrant.query.filter_by(
        document_id=document.id,
        user_id=user.id,
    ).first()

    if grant is None:
        return False

    if action == "read":
        return grant.permission in ("read", "edit")

    if action == "edit":
        return grant.permission == "edit"

    return False
