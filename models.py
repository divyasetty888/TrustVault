from flask_login import UserMixin
from datetime import datetime, timezone
from extension import db


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="viewer")
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )


class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(
        db.Integer, db.ForeignKey("user.id"), nullable=False, index=True
    )
    title = db.Column(db.String(255), nullable=False, index=True)
    category = db.Column(db.String(100), nullable=False, default="General")
    storage_key = db.Column(db.String(255), unique=True, nullable=False)
    content_hash = db.Column(db.String(64), nullable=False)
    is_deleted = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )


class DocumentGrant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(
        db.Integer, db.ForeignKey("document.id"), nullable=False, index=True
    )
    user_id = db.Column(
        db.Integer, db.ForeignKey("user.id"), nullable=False, index=True
    )
    permission = db.Column(db.String(10), nullable=False)
    granted_by = db.Column(
        db.Integer, db.ForeignKey("user.id"), nullable=False
    )
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        db.UniqueConstraint("document_id", "user_id", name="uq_document_user"),
        db.CheckConstraint(
            "permission IN ('read', 'edit')",
            name="ck_grant_permission",
        ),
    )


class AuditEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    actor_id = db.Column(
        db.Integer, db.ForeignKey("user.id"), nullable=True, index=True
    )
    document_id = db.Column(
        db.Integer, db.ForeignKey("document.id"), nullable=True, index=True
    )
    action = db.Column(db.String(100), nullable=False)
    outcome = db.Column(db.String(20), nullable=False)
    timestamp = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    previous_hash = db.Column(db.String(64), nullable=True)
    event_hash = db.Column(db.String(64), nullable=False, unique=True)
    details = db.Column(db.JSON, nullable=False, default=dict)
