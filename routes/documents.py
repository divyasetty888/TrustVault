"""Secure document listing, upload, and download routes for TrustVault."""

import hashlib
from datetime import datetime, timezone

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from flask_login import current_user, login_required
from sqlalchemy import or_

from extension import db
from models import Document, DocumentGrant, User
from permissions import can_access_document
from audit import record_event
from storage import get_stored_file, save_upload, validate_upload


documents_bp = Blueprint("documents", __name__, url_prefix="/documents")


def _audit_denied(document, attempted_document_id, action, reason):
    """Record a denied attempt without relying on a possibly missing document FK."""
    record_event(
        actor_id=current_user.id,
        document_id=document.id if document is not None else None,
        action=action,
        outcome="denied",
        details={
            "attempted_document_id": attempted_document_id,
            "reason": reason,
        },
    )
    db.session.commit()


def _visible_documents():
    """Return non-deleted documents the current user may potentially see."""
    query = Document.query.filter_by(is_deleted=False)

    if getattr(current_user, "role", None) == "admin":
        return query

    granted_ids = db.session.query(DocumentGrant.document_id).filter_by(
        user_id=current_user.id
    )
    return query.filter(
        or_(
            Document.owner_id == current_user.id,
            Document.id.in_(granted_ids),
        )
    )


@documents_bp.get("/")
@login_required
def list_documents():
    """List and search only documents visible to the logged-in user."""
    query = _visible_documents()

    name = request.args.get("name", "").strip()
    owner_email = request.args.get("owner", "").strip()
    category = request.args.get("category", "").strip()
    date_from = request.args.get("date_from", "").strip()
    date_to = request.args.get("date_to", "").strip()

    if name:
        query = query.filter(Document.title.ilike(f"%{name}%"))
    if category:
        query = query.filter(Document.category.ilike(f"%{category}%"))
    if owner_email:
        query = query.join(User, User.id == Document.owner_id).filter(
            User.email.ilike(f"%{owner_email}%")
        )

    if date_from:
        try:
            query = query.filter(
                Document.created_at >= datetime.strptime(date_from, "%Y-%m-%d")
            )
        except ValueError:
            flash("Invalid start date. Use YYYY-MM-DD.", "error")
            return redirect(url_for("documents.list_documents"))

    if date_to:
        try:
            # Inclusive date: compare against midnight after the selected date.
            end_exclusive = datetime.strptime(date_to, "%Y-%m-%d") 
            from datetime import timedelta
            end_exclusive += timedelta(days=1)
            query = query.filter(Document.created_at < end_exclusive)
        except ValueError:
            flash("Invalid end date. Use YYYY-MM-DD.", "error")
            return redirect(url_for("documents.list_documents"))

    documents = query.order_by(Document.created_at.desc()).all()
    # Fail closed: apply the same read policy used by download routes.
    documents = [
        doc for doc in documents
        if can_access_document(current_user, doc, "read")
    ]

    return render_template(
        "documents.html",
        documents=documents,
        filters={
            "name": name,
            "owner": owner_email,
            "category": category,
            "date_from": date_from,
            "date_to": date_to,
        },
    )


@documents_bp.post("/upload")
@login_required
def upload_document():
    """Validate and store an uploaded file as a private, randomly named object."""
    if getattr(current_user, "role", None) not in ("owner", "admin"):
        record_event(
            actor_id=current_user.id,
            document_id=None,
            action="document_upload",
            outcome="denied",
            details={"reason": "role_not_allowed"},
        )
        db.session.commit()
        abort(403)

    uploaded_file = request.files.get("file")
    safe_original_name, validation_result = validate_upload(uploaded_file)
    if safe_original_name is None:
        flash(validation_result, "error")
        return redirect(url_for("documents.list_documents"))

    extension = validation_result
    title = request.form.get("title", "").strip()
    category = request.form.get("category", "").strip()

    if not title or len(title) > 200:
        flash("Enter a title of 1–200 characters.", "error")
        return redirect(url_for("documents.list_documents"))
    if len(category) > 100:
        flash("Category must be 100 characters or fewer.", "error")
        return redirect(url_for("documents.list_documents"))

    # Save first, then persist metadata. Delete the stored file if DB work fails.
    storage_key = None
    try:
        storage_key, file_path = save_upload(uploaded_file, extension)
        digest = hashlib.sha256(file_path.read_bytes()).hexdigest()
        document = Document(
            owner_id=current_user.id,
            title=title,
            category=category or None,
            storage_key=storage_key,
            content_hash=digest,
            is_deleted=False,
            created_at=datetime.now(timezone.utc),
        )
        db.session.add(document)
        db.session.flush()

        record_event(
            actor_id=current_user.id,
            document_id=document.id,
            action="document_upload",
            outcome="success",
            details={
                "title": title,
                "category": category or None,
                "storage_key": storage_key,
                "content_hash": digest,
            },
        )
        db.session.commit()
    except Exception:
        db.session.rollback()
        if storage_key:
            path = get_stored_file(storage_key)
            if path:
                path.unlink(missing_ok=True)
        current_app.logger.exception("Document upload failed")
        abort(500)

    flash("Document uploaded successfully.", "success")
    return redirect(url_for("documents.list_documents"))


@documents_bp.get("/<int:document_id>/download")
@login_required
def download_document(document_id):
    """Download a document only after a fresh authorization check."""
    document = db.session.get(Document, document_id)

    if not can_access_document(current_user, document, "read"):
        _audit_denied(
            document,
            document_id,
            action="document_download",
            reason="not_found_or_not_authorized",
        )
        # Return the same status for missing and unauthorized IDs.
        abort(404)

    stored_path = get_stored_file(document.storage_key)
    if stored_path is None:
        record_event(
            actor_id=current_user.id,
            document_id=document.id,
            action="document_download",
            outcome="error",
            details={"reason": "stored_file_missing"},
        )
        db.session.commit()
        abort(404)

    record_event(
        actor_id=current_user.id,
        document_id=document.id,
        action="document_download",
        outcome="success",
        details={"storage_key": document.storage_key},
    )
    db.session.commit()

    # Use a generic download name, not the private storage key.
    download_name = f"document-{document.id}"
    return send_file(
        stored_path,
        as_attachment=True,
        download_name=download_name,
        conditional=True,
    )
