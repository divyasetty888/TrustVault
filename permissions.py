
from extension import db
from models import DocumentGrant

def can_access_document(user, document, action):
    # Default deny.
    if user is None or not user.is_active:
        return False

    if document is None or document.is_deleted:
        return False

    # Ownership grants access to the owner's document.
    if document.owner_id == user.id:
        return True

    # Administrators do not automatically bypass document permissions.
    grant = db.session.execute(
        db.select(DocumentGrant).where(
            DocumentGrant.document_id == document.id,
            DocumentGrant.user_id == user.id,
        )
    ).scalar_one_or_none()

    if grant is None:
        return False

    if action == "read":
        return grant.permission in ("read", "edit")

    if action == "edit":
        return grant.permission == "edit"

    # Delete, grant, revoke and other privileged actions are owner-only.
    return False