"""Private file storage helpers for TrustVault.

Uploaded files are stored under Flask's instance directory, not under static/
or another public web directory. The stored filename is a random UUID-based key;
the original client filename is never used as the storage path.
"""

from pathlib import Path
from uuid import uuid4

from flask import current_app
from werkzeug.utils import secure_filename


ALLOWED_EXTENSIONS = {"pdf", "txt", "png", "jpg", "jpeg", "docx"}


def _private_storage_dir() -> Path:
    """Return the private upload directory, creating it if necessary."""
    storage_dir = Path(current_app.instance_path) / "private_uploads"
    storage_dir.mkdir(parents=True, exist_ok=True)
    return storage_dir


def validate_upload(upload):
    """Validate a Flask upload by filename extension.

    Returns (safe_original_filename, extension) on success, or
    (None, error_message) on failure.

    Note: extension allowlisting is a basic check, not proof of file content.
    Production systems should also inspect file signatures and consider malware
    scanning before making uploaded content available to users.
    """
    if upload is None or not getattr(upload, "filename", ""):
        return None, "No file was selected."

    safe_name = secure_filename(upload.filename)
    if not safe_name or "." not in safe_name:
        return None, "Invalid filename or missing file extension."

    extension = safe_name.rsplit(".", 1)[1].lower()
    if extension not in ALLOWED_EXTENSIONS:
        return None, "File type is not allowed."

    return safe_name, extension


def save_upload(upload, extension):
    """Save an already-validated upload using a random storage key.

    Returns (storage_key, absolute_path). Store only storage_key in the database.
    The extension is retained for convenience, but the original filename is not.
    """
    extension = str(extension).lower().lstrip(".")
    if extension not in ALLOWED_EXTENSIONS:
        raise ValueError("Unsupported file extension.")

    storage_key = f"{uuid4().hex}.{extension}"
    storage_dir = _private_storage_dir()
    destination = storage_dir / storage_key

    # UUID collision is extraordinarily unlikely; exclusive creation prevents
    # accidentally overwriting a file if one ever occurs.
    upload.save(destination)
    return storage_key, destination


def get_stored_file(storage_key):
    """Resolve a stored key safely, rejecting path traversal and missing files."""
    if not storage_key or Path(storage_key).name != storage_key:
        return None

    # Reject both POSIX and Windows path separators regardless of host OS.
    if "/" in storage_key or "\\" in storage_key:
        return None

    storage_dir = _private_storage_dir().resolve()
    candidate = (storage_dir / storage_key).resolve()

    if candidate.parent != storage_dir or not candidate.is_file():
        return None

    return candidate
