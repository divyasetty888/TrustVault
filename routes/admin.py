
from flask import Blueprint, abort, render_template
from flask_login import current_user, login_required

from models import AuditEvent
from audit import verify_audit_chain

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


@admin_bp.get("/audit")
@login_required
def audit_log():
    # Only administrators may view the audit log.
    if current_user.role != "admin":
        abort(403)

    events = (
        AuditEvent.query
        .order_by(AuditEvent.id.desc())
        .limit(100)
        .all()
    )

    chain_valid, failing_event_id = verify_audit_chain()

    return render_template(
        "admin_audit.html",
        events=events,
        chain_valid=chain_valid,
        failing_event_id=failing_event_id,
    )
