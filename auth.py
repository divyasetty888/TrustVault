from flask import (
    Blueprint, render_template, request,
    redirect, url_for, flash
)
from flask_login import (
    login_user, logout_user, login_required, current_user
)
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
from extension import db, login_manager
from models import User

auth = Blueprint("auth", __name__)
password_hasher = PasswordHasher()


@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except (ValueError, TypeError):
        return None


@auth.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = db.session.execute(
            db.select(User).where(User.email == email)
        ).scalar_one_or_none()

        authenticated = False

        if user and user.is_active:
            try:
                password_hasher.verify(user.password_hash, password)
                authenticated = True
            except (VerifyMismatchError, VerificationError):
                authenticated = False

        if not authenticated:
            flash("Invalid email or password.", "error")
            return render_template("login.html"), 401

        # Avoid carrying forward a session established before login.
        from flask import session
        session.clear()
        login_user(user, fresh=True)

        return redirect(url_for("dashboard.index"))

    return render_template("login.html")


@auth.post("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))


@auth.get("/me")
@login_required
def me():
    return {
        "id": current_user.id,
        "email": current_user.email,
        "role": current_user.role,
    }