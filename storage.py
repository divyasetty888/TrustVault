
"""Private file storage helpers for TrustVault.

Uploaded files are stored under Flask's instance directory, not under static/
or another public web directory. Random storage keys are used instead of
original client filenames.
"""

from pathlib import Path
from uuid import uuid4
import zipfile

from flask import current_app
from werkzeug.utils import secure_filename


ALLOWED_EXTENSIONS = {"pdf", "txt", "png", "jpg", "jpeg", "docx"}


def _private_storage_dir() -> Path:
    """Return the private upload directory, creating it if necessary."""
    storage_dir = Path(current_app.instance_path) / "private_uploads"
    storage_dir.mkdir(parents=True, exist_ok=True)
    return storage_dir


def validate_upload(upload):
    """Check the filename extension and basic file signature."""
    if upload is None or not getattr(upload, "filename", ""):
        return None, "No file was selected."

    safe_name = secure_filename(upload.filename)
    if not safe_name or "." not in safe_name:
        return None, "Invalid filename or missing file extension."

    extension = safe_name.rsplit(".", 1)[1].lower()
    if extension not in ALLOWED_EXTENSIONS:
        return None, "File type is not allowed."

    stream = upload.stream

    try:
        stream.seek(0)

        if extension == "docx":
            try:
                with zipfile.ZipFile(stream) as archive:
                    names = set(archive.namelist())
                    if (
                        "[Content_Types].xml" not in names
                        or "word/document.xml" not in names
                    ):
                        return None, "The file is not a valid DOCX document."
            except (zipfile.BadZipFile, OSError):
                return None, "The file is not a valid DOCX document."
            finally:
                stream.seek(0)

        else:
            header = stream.read(8)
            stream.seek(0)

            if extension == "pdf" and not header.startswith(b"%PDF-"):
                return None, "The file content does not match its extension."

            if extension == "png" and header != b"\x89PNG\r\n\x1a\n":
                return None, "The file content does not match its extension."

            if extension in ("jpg", "jpeg") and not header.startswith(b"\xff\xd8\xff"):
                return None, "The file content does not match its extension."

    except (OSError, ValueError):
        try:
            stream.seek(0)
        except (OSError, ValueError):
            pass
        return None, "Unable to read the uploaded file."

    return safe_name, extension


def save_upload(upload, extension):
    """Save a validated upload using a random storage key."""
    extension = str(extension).lower().lstrip(".")
    if extension not in ALLOWED_EXTENSIONS:
        raise ValueError("Unsupported file extension.")

    storage_key = f"{uuid4().hex}.{extension}"
    storage_dir = _private_storage_dir()
    destination = storage_dir / storage_key

    # Exclusive creation prevents overwriting an existing file.
    with destination.open("xb") as output:
        while True:
            chunk = upload.stream.read(64 * 1024)
            if not chunk:
                break
            output.write(chunk)

    return storage_key, destination


def get_stored_file(storage_key):
    """Safely resolve a stored key, rejecting traversal and missing files."""
    if not storage_key or Path(storage_key).name != storage_key:
        return None

    if "/" in storage_key or "\\" in storage_key:
        return None

    storage_dir = _private_storage_dir().resolve()
    candidate = (storage_dir / storage_key).resolve()

    if candidate.parent != storage_dir or not candidate.is_file():
        return None

    return candidate