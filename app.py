import os
from dotenv import load_dotenv
from flask import Flask, jsonify, redirect, url_for
from extension import db, login_manager, csrf
load_dotenv()
def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    os.makedirs(app.instance_path, exist_ok=True)
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY"),
        SQLALCHEMY_DATABASE_URI=os.environ.get(
            "DATABASE_URL", "sqlite:///trustvault.sqlite3"
        ),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=(
            os.environ.get("COOKIE_SECURE", "false").lower() == "true"
        ),
        MAX_CONTENT_LENGTH=5 * 1024 * 1024,
    )
    if test_config:
        app.config.update(test_config)
    if not app.config.get("SECRET_KEY"):
        raise RuntimeError(
            "Set SECRET_KEY in your environment before starting."
        )
    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    # Register authentication routes
    from auth import auth
    app.register_blueprint(auth, url_prefix="/api/auth")
    login_manager.login_view = "auth.login"
    # Register dashboard routes
    from routes.dashboard import dashboard_bp
    app.register_blueprint(
        dashboard_bp,
        url_prefix="/dashboard",
    )
    from routes.documents import documents_bp
    app.register_blueprint(documents_bp)
    from routes.sharing import sharing_bp
    app.register_blueprint(sharing_bp)
    from routes.admin import admin_bp
    app.register_blueprint(admin_bp)
    # Import models and create database tables
    from models import User, Document, DocumentGrant, AuditEvent
    with app.app_context():
        db.create_all()
    # Health-check route
    @app.get("/health")
    def health():
        return jsonify(
            status="ok",
            application="TrustVault",
        ), 200
    # Root URL redirects to the dashboard
    @app.get("/")
    def home():
        return redirect(url_for("dashboard.index"))
    return app
app = create_app()
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
