# TrustVault — Secure Document Sharing Platform

TrustVault is a secure document-sharing web application built with Python and Flask. It provides authentication, role-based access control, document uploads and downloads, controlled sharing, and audit logging.

## Features

- User authentication with Argon2 password hashing.
- Role-based access control for owners, viewers, and administrators.
- Document upload and download with permission checks.
- Read and edit access grants, including revocation.
- File validation and file-size limits.
- SHA-256 file integrity hashes.
- Audit events with hash-chain verification.
- Automated tests for permissions and security-sensitive routes.

## Technology Stack

- Python
- Flask
- Flask-SQLAlchemy and SQLAlchemy
- Flask-Login
- Flask-WTF
- Argon2
- SQLite for local development
- pytest

## Setup on Windows

1. Install Python and Git.
2. Clone the repository and enter the project directory:

   ```powershell
   git clone https://github.com/divyasetty888/TrustVault.git
   cd TrustVault
   ```

3. Create and activate a virtual environment:

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

4. Install dependencies:

   ```powershell
   python -m pip install -r requirements.txt
   ```

5. Create a local `.env` file with a strong, private `SECRET_KEY`. Configure `DATABASE_URL` if needed. Never commit `.env` or share its secret values.

6. Start the development server:

   ```powershell
   python app.py
   ```

7. Open `http://127.0.0.1:5000` in your browser.

## Demo Accounts

Use the project's demo-seeding script to create accounts interactively:

```powershell
python scripts/seed_demo.py
```

Follow the prompts and use unique, strong passwords. Do not commit demo passwords or production credentials.

## Run Tests

```powershell
python -m pytest -q
```

The current local test suite has 14 passing tests. Run the tests again after making changes.

## Security Notes

- Keep secrets in environment variables, not source control.
- Use HTTPS and secure cookie settings in production.
- Do not run Flask's built-in development server with debug mode in production.
- Review `THREATS.md` for documented threats, mitigations, assumptions, and remaining risks.
- Audit hash chains can help detect event changes but are not tamper-proof against an attacker who can rewrite the database and recompute the entire chain.

## Project Status

This is a hiring-challenge project. Security depends on the deployment configuration and the completeness of testing; passing automated tests alone does not establish that the application is production-ready.
