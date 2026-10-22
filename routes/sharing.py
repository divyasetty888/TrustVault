
from flask import Blueprint, abort, flash, redirect, request, url_for
from flask_login import current_user, login_required

from extension import db
from models import Document, DocumentGrant, User
from audit import record_event


sharing_bp = Blueprint(
    "sharing",
    __name__,
    url_prefix="/sharing",
)


def get_owned_document(document_id):
    """Only the document owner can manage its grants."""
    document = db.session.get(Document, document_id)

    if document is None or document.is_deleted:
        abort(404)

    if document.owner_id != current_user.id:
        record_event(
            actor_id=current_user.id,
            document_id=document.id,
            action="manage_document_sharing",
            outcome="denied",
            details={"reason": "not_document_owner"},
        )
        db.session.commit()
        abort(404)

    return document


@sharing_bp.post("/<int:document_id>/grant")
@login_required
def grant_access(document_id):
    """Grant an existing active user read or edit permission."""
    document = get_owned_document(document_id)

    email = request.form.get("email", "").strip().lower()
    permission = request.form.get("permission", "").strip().lower()

    if not email or permission not in ("read", "edit"):
        flash("Enter a user's email and choose read or edit permission.", "error")
        return redirect(url_for("documents.list_documents"))

    recipient = User.query.filter_by(email=email).first()

    if recipient is None or not recipient.is_active:
        flash("No active user was found with that email.", "error")
        return redirect(url_for("documents.list_documents"))

    if recipient.id == current_user.id:
        flash("You already own this document.", "error")
        return redirect(url_for("documents.list_documents"))

    grant = DocumentGrant.query.filter_by(
        document_id=document.id,
        user_id=recipient.id,
    ).first()

    if grant is None:
        grant = DocumentGrant(
            document_id=document.id,
            user_id=recipient.id,
            permission=permission,
            granted_by=current_user.id,
        )
        db.session.add(grant)
        action = "document_access_granted"
    else:
        grant.permission = permission
        grant.granted_by = current_user.id
        action = "document_access_updated"

    record_event(
        actor_id=current_user.id,
        document_id=document.id,
        action=action,
        outcome="success",
        details={
            "recipient_user_id": recipient.id,
            "permission": permission,
        },
    )

    db.session.commit()
    flash("Document access saved successfully.", "success")
    return redirect(url_for("documents.list_documents"))


@sharing_bp.post("/<int:document_id>/revoke/<int:user_id>")
@login_required
def revoke_access(document_id, user_id):
    """Revoke an existing user's grant immediately."""
    document = get_owned_document(document_id)

    grant = DocumentGrant.query.filter_by(
        document_id=document.id,
        user_id=user_id,
    ).first()

    if grant is None:
        flash("No access grant was found for that user.", "error")
        return redirect(url_for("documents.list_documents"))

    record_event(
        actor_id=current_user.id,
        document_id=document.id,
        action="document_access_revoked",
        outcome="success",
        details={
            "recipient_user_id": user_id,
            "previous_permission": grant.permission,
        },
    )

    db.session.delete(grant)
    db.session.commit()

    flash("Document access revoked successfully.", "success")
    return redirect(url_for("documents.list_documents"))
