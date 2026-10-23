
"""Private Supabase S3-compatible storage helpers for TrustVault."""

import os
import zipfile
from pathlib import PurePosixPath
from uuid import uuid4

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, BotoCoreError
from flask import current_app
from werkzeug.utils import secure_filename


ALLOWED_EXTENSIONS = {"pdf", "txt", "png", "jpg", "jpeg", "docx"}


def _storage_config():
    """Read required storage settings from environment variables."""
    required = (
        "SUPABASE_S3_ENDPOINT",
        "SUPABASE_S3_REGION",
        "SUPABASE_S3_BUCKET",
        "SUPABASE_S3_ACCESS_KEY_ID",
        "SUPABASE_S3_SECRET_ACCESS_KEY",
    )

    config = {key: os.environ.get(key) for key in required}
    missing = [key for key, value in config.items() if not value]

    if missing:
        raise RuntimeError(
            "Missing required storage configuration: " + ", ".join(missing)
        )

    return config


def _s3_client():
    """Create an S3-compatible client for Supabase Storage."""
    config = _storage_config()

    return boto3.client(
        "s3",
        endpoint_url=config["SUPABASE_S3_ENDPOINT"],
        region_name=config["SUPABASE_S3_REGION"],
        aws_access_key_id=config["SUPABASE_S3_ACCESS_KEY_ID"],
        aws_secret_access_key=config["SUPABASE_S3_SECRET_ACCESS_KEY"],
        config=Config(
            signature_version="s3v4",
            retries={"max_attempts": 3, "mode": "standard"},
        ),
    )


def _valid_storage_key(storage_key):
    """Reject empty keys and path traversal attempts."""
    if not isinstance(storage_key, str) or not storage_key:
        return False

    if "/" in storage_key or "\\" in storage_key:
        return False

    return PurePosixPath(storage_key).name == storage_key


def validate_upload(upload):
    """Validate the filename and basic signatures of supported file types."""
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

        elif extension in {"pdf", "png", "jpg", "jpeg"}:
            header = stream.read(8)

            valid = (
                extension == "pdf" and header.startswith(b"%PDF-")
            ) or (
                extension == "png" and header == b"\x89PNG\r\n\x1a\n"
            ) or (
                extension in {"jpg", "jpeg"}
                and header.startswith(b"\xff\xd8\xff")
            )

            if not valid:
                return None, "The file content does not match its extension."

    except (OSError, ValueError):
        return None, "Unable to read the uploaded file."

    finally:
        try:
            stream.seek(0)
        except (OSError, ValueError):
            pass

    return safe_name, extension


def save_upload(upload, extension):
    """Upload a validated file to the configured private bucket."""
    extension = str(extension).lower().lstrip(".")

    if extension not in ALLOWED_EXTENSIONS:
        raise ValueError("Unsupported file extension.")

    config = _storage_config()
    storage_key = f"{uuid4().hex}.{extension}"

    upload.stream.seek(0)

    try:
        _s3_client().upload_fileobj(
            upload.stream,
            config["SUPABASE_S3_BUCKET"],
            storage_key,
            ExtraArgs={"ContentType": "application/octet-stream"},
        )

    except (ClientError, BotoCoreError):
        current_app.logger.exception("Supabase upload failed")
        raise

    finally:
        try:
            upload.stream.seek(0)
        except (OSError, ValueError):
            pass

    return storage_key, None


def get_stored_file(storage_key):
    """Return an object's bytes without exposing a public URL."""
    if not _valid_storage_key(storage_key):
        return None

    config = _storage_config()

    try:
        response = _s3_client().get_object(
            Bucket=config["SUPABASE_S3_BUCKET"],
            Key=storage_key,
        )

        try:
            return response["Body"].read()
        finally:
            response["Body"].close()

    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")

        if code in {"NoSuchKey", "404", "NotFound"}:
            return None

        current_app.logger.exception("Supabase download failed")
        raise

    except BotoCoreError:
        current_app.logger.exception("Supabase download failed")
        raise


def delete_stored_file(storage_key):
    """Delete an object from the configured bucket."""
    if not _valid_storage_key(storage_key):
        return False

    config = _storage_config()

    try:
        _s3_client().delete_object(
            Bucket=config["SUPABASE_S3_BUCKET"],
            Key=storage_key,
        )
        return True

    except (ClientError, BotoCoreError):
        current_app.logger.exception("Supabase object deletion failed")
        raise
