
import pytest
from flask import url_for
from flask_login import login_user
from io import BytesIO
from extension import db
from models import User


def login_as(client, app, user_id):
    with app.app_context():
        user = db.session.get(User, user_id)
        with client.session_transaction() as session:
            session["_user_id"] = str(user.id)
            session["_fresh"] = True


def test_dashboard_redirects_when_logged_out(app):
    client = app.test_client()

    response = client.get("/dashboard/")

    assert response.status_code in (302, 401)


def test_viewer_cannot_access_admin_audit(app):
    client = app.test_client()
    viewer_id = app.config["TEST_DATA"]["viewer_id"]

    login_as(client, app, viewer_id)
    response = client.get("/admin/audit")

    assert response.status_code == 403


def test_admin_can_access_admin_audit(app):
    client = app.test_client()
    admin_id = app.config["TEST_DATA"]["admin_id"]

    login_as(client, app, admin_id)
    response = client.get("/admin/audit")

    assert response.status_code == 200


def test_user_without_grant_cannot_download_document(app):
    client = app.test_client()
    data = app.config["TEST_DATA"]

    login_as(client, app, data["other_id"])
    response = client.get(
        f"/documents/{data['document_id']}/download"
    )

    assert response.status_code == 404


def test_missing_document_download_returns_404(app):
    client = app.test_client()
    owner_id = app.config["TEST_DATA"]["owner_id"]

    login_as(client, app, owner_id)
    response = client.get("/documents/999999/download")

    assert response.status_code == 404
from argon2 import PasswordHasher
from extension import db
from models import AuditEvent, User
from audit import record_event, verify_audit_chain


def test_inactive_user_cannot_log_in(app):
    """Inactive accounts must be rejected even with the correct password."""
    with app.app_context():
        inactive_user = User(
            email="inactive@example.com",
            password_hash=PasswordHasher().hash("Inactive-test-password-123"),
            role="viewer",
            is_active=False,
        )
        db.session.add(inactive_user)
        db.session.commit()

    client = app.test_client()
    response = client.post(
        "/api/auth/login",
        data={
            "email": "inactive@example.com",
            "password": "Inactive-test-password-123",
        },
        follow_redirects=False,
    )

    assert response.status_code == 401
    assert b"Invalid email or password." in response.data


def test_audit_chain_validates_after_events(app):
    """Normal audit events should pass verification."""
    with app.app_context():
        record_event(
            actor_id=app.config["TEST_DATA"]["owner_id"],
            document_id=app.config["TEST_DATA"]["document_id"],
            action="test_event_one",
            outcome="success",
            details={"purpose": "security test"},
        )
        record_event(
            actor_id=app.config["TEST_DATA"]["owner_id"],
            document_id=app.config["TEST_DATA"]["document_id"],
            action="test_event_two",
            outcome="success",
            details={"purpose": "chain test"},
        )
        db.session.commit()

        is_valid, failing_event_id = verify_audit_chain()

        assert is_valid is True
        assert failing_event_id is None


def test_audit_chain_detects_event_tampering(app):
    """Changing stored event details should invalidate its hash."""
    with app.app_context():
        event = record_event(
            actor_id=app.config["TEST_DATA"]["owner_id"],
            document_id=app.config["TEST_DATA"]["document_id"],
            action="test_tamper_detection",
            outcome="success",
            details={"status": "original"},
        )
        db.session.commit()

        event_id = event.id

        stored_event = db.session.get(AuditEvent, event_id)
        stored_event.details = '{"status":"changed"}'
        db.session.commit()

        is_valid, failing_event_id = verify_audit_chain()

        assert is_valid is False
        assert failing_event_id == event_id
        
def test_non_owner_cannot_grant_access(app):
    """A user who does not own a document cannot share it."""
    client = app.test_client()
    data = app.config["TEST_DATA"]

    login_as(client, app, data["other_id"])
    response = client.post(
        f"/sharing/{data['document_id']}/grant",
        data={
            "email": "other@example.com",
            "permission": "read",
        },
    )

    assert response.status_code == 404


def test_non_owner_cannot_revoke_access(app):
    """A user who does not own a document cannot revoke a grant."""
    client = app.test_client()
    data = app.config["TEST_DATA"]

    login_as(client, app, data["other_id"])
    response = client.post(
        f"/sharing/{data['document_id']}/revoke/{data['viewer_id']}"
    )

    assert response.status_code == 404


def test_owner_can_grant_read_access(app):
    """The owner can grant read access to another user."""
    client = app.test_client()
    data = app.config["TEST_DATA"]

    login_as(client, app, data["owner_id"])
    response = client.post(
        f"/sharing/{data['document_id']}/grant",
        data={
            "email": "other@example.com",
            "permission": "read",
        },
    )

    assert response.status_code == 302

    with app.app_context():
        from models import DocumentGrant

        grant = DocumentGrant.query.filter_by(
            document_id=data["document_id"],
            user_id=data["other_id"],
        ).first()

        assert grant is not None
        assert grant.permission == "read"


def test_revoked_user_can_no_longer_download(app):
    """Revoking a grant prevents subsequent downloads."""
    client = app.test_client()
    data = app.config["TEST_DATA"]

    login_as(client, app, data["owner_id"])
    response = client.post(
        f"/sharing/{data['document_id']}/revoke/{data['viewer_id']}"
    )

    assert response.status_code == 302

    login_as(client, app, data["viewer_id"])
    response = client.get(
        f"/documents/{data['document_id']}/download"
    )

    assert response.status_code == 404
    
from io import BytesIO


def test_viewer_cannot_upload_document(app):
    """A viewer must not be allowed to upload documents."""
    client = app.test_client()
    viewer_id = app.config["TEST_DATA"]["viewer_id"]

    login_as(client, app, viewer_id)
    response = client.post(
        "/documents/upload",
        data={
            "title": "Test upload",
            "file": (BytesIO(b"test content"), "test.txt"),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 403



def test_upload_rejects_disallowed_file_extension(app):
    """Executable files must be rejected."""
    client = app.test_client()
    owner_id = app.config["TEST_DATA"]["owner_id"]

    login_as(client, app, owner_id)
    response = client.post(
        "/documents/upload",
        data={
            "title": "Unsafe file",
            "file": (BytesIO(b"not a document"), "malware.exe"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"File type is not allowed." in response.data

def test_upload_rejects_missing_file(app):
    """An upload request without a file must be rejected."""
    client = app.test_client()
    owner_id = app.config["TEST_DATA"]["owner_id"]

    login_as(client, app, owner_id)
    response = client.post(
        "/documents/upload",
        data={"title": "Missing file"},
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"No file was selected." in response.data
    
def test_oversized_upload_is_rejected(app):
    """Uploads larger than the configured limit must be rejected."""
    client = app.test_client()
    owner_id = app.config["TEST_DATA"]["owner_id"]

    login_as(client, app, owner_id)

    response = client.post(
        "/documents/upload",
        data={
            "title": "Oversized file",
            "file": (
                BytesIO(b"A" * (5 * 1024 * 1024 + 1)),
                "large.txt",
            ),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 413