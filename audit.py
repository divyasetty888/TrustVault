"""Tamper-evident audit-event creation for TrustVault.

Assumes AuditEvent has these fields:
actor_id, document_id, action, outcome, timestamp,
previous_hash, event_hash, details.

The details field is stored as a JSON-encoded string. If your model defines
details as a SQLAlchemy JSON column instead of Text/String, change
details=details_json to details=details or {} below.
"""

import hashlib
import json
from datetime import datetime, timezone

from extension import db
from models import AuditEvent
def _utc_isoformat(value):
    """Return a consistent UTC timestamp string for audit hashing."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    else:
        value = value.astimezone(timezone.utc)

    return value.isoformat()


def record_event(actor_id, document_id, action, outcome, details=None):
    """Create and add an audit event to the current database transaction.

    Call db.session.commit() in the route/service after the related operation
    succeeds. For a denied attempt, record the event and commit it even when
    the requested operation is rejected.

    Returns the new AuditEvent. This function does not commit by itself.
    """
    previous = (
        AuditEvent.query
        .order_by(AuditEvent.id.desc())
        .first()
    )
    previous_hash = previous.event_hash if previous else "GENESIS"

    timestamp = datetime.now(timezone.utc)
    details_json = json.dumps(
        details or {},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    # Hash a canonical representation so key ordering does not change the hash.
    event_data = {
        "actor_id": actor_id,
        "document_id": document_id,
        "action": action,
        "outcome": outcome,
        "timestamp": _utc_isoformat(timestamp),
        "previous_hash": previous_hash,
        "details": json.loads(details_json),
    }
    canonical_event = json.dumps(
        event_data,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    event_hash = hashlib.sha256(canonical_event.encode("utf-8")).hexdigest()

    event = AuditEvent(
        actor_id=actor_id,
        document_id=document_id,
        action=action,
        outcome=outcome,
        timestamp=timestamp,
        previous_hash=previous_hash,
        event_hash=event_hash,
        details=details_json,
    )
    db.session.add(event)
    db.session.flush()
    return event


def verify_audit_chain():
    """Return (is_valid, failing_event_id).

    Checks the links and recomputes each event hash in ID order. Returns
    (True, None) when all stored events validate. This detects many accidental
    or partial changes, but a database administrator who can rewrite the
    entire chain may be able to recalculate it; stronger protection requires
    an external append-only log or periodically anchored hash.
    """
    expected_previous_hash = "GENESIS"

    events = AuditEvent.query.order_by(AuditEvent.id.asc()).all()
    for event in events:
        try:
            details_value = event.details
            if isinstance(details_value, str):
                details_value = json.loads(details_value) if details_value else {}
            details_value = details_value or {}

            event_data = {
                "actor_id": event.actor_id,
                "document_id": event.document_id,
                "action": event.action,
                "outcome": event.outcome,
                "timestamp": _utc_isoformat(event.timestamp),
                "previous_hash": event.previous_hash,
                "details": details_value,
            }
            canonical_event = json.dumps(
                event_data,
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            )
            calculated_hash = hashlib.sha256(
                canonical_event.encode("utf-8")
            ).hexdigest()

            if event.previous_hash != expected_previous_hash:
                return False, event.id
            if event.event_hash != calculated_hash:
                return False, event.id

            expected_previous_hash = event.event_hash
        except (TypeError, ValueError, AttributeError):
            return False, event.id

    return True, None
