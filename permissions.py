
from extension import db

from models import DocumentGrant


def can_access_document(user, document, action):
    # Reject missing or inactive users
    if user is None or not user.is_active:
        return False

    # Validate the requested action before granting any access
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
