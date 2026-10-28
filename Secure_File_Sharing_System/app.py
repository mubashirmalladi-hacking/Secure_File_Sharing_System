
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from functools import wraps

from dotenv import load_dotenv
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, send_file, abort
)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from cryptography.fernet import Fernet, InvalidToken
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from io import BytesIO

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config["SQLALCHEMY_DATABASE_URI"] = (
    "sqlite:///" + str(BASE_DIR / "files.db")
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = (
    os.getenv("COOKIE_SECURE", "false").lower() == "true"
)

if not app.config["SECRET_KEY"]:
    raise RuntimeError("Set SECRET_KEY in your .env file.")

fernet_key = os.getenv("FERNET_KEY")
if not fernet_key:
    raise RuntimeError("Set FERNET_KEY in your .env file.")

cipher = Fernet(fernet_key.encode())
db = SQLAlchemy(app)
csrf = CSRFProtect(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="user", nullable=False)


class StoredFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_name = db.Column(db.String(255), nullable=False)
    stored_name = db.Column(db.String(80), unique=True, nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    uploaded_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )


class FilePermission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(
        db.Integer, db.ForeignKey("stored_file.id"), nullable=False
    )
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    __table_args__ = (
        db.UniqueConstraint("file_id", "user_id", name="unique_file_permission"),
    )


class DownloadLink(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token_hash = db.Column(db.String(64), unique=True, nullable=False)
    file_id = db.Column(
        db.Integer, db.ForeignKey("stored_file.id"), nullable=False
    )
    created_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)
    used = db.Column(db.Boolean, default=False, nullable=False)


def current_user():
    user_id = session.get("user_id")
    return db.session.get(User, user_id) if user_id else None

@app.context_processor
def inject_current_user():
    return {"current_user": current_user}

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if not user:
            return redirect(url_for("login"))
        if user.role != "admin":
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def can_access_file(file_record, user):
    if not user or not file_record:
        return False
    if user.role == "admin" or file_record.owner_id == user.id:
        return True
    permission = FilePermission.query.filter_by(
        file_id=file_record.id, user_id=user.id
    ).first()
    return permission is not None


def encrypt_and_save(file_storage):
    encrypted = cipher.encrypt(file_storage.read())
    stored_name = secrets.token_hex(24) + ".enc"
    path = UPLOAD_DIR / stored_name
    path.write_bytes(encrypted)
    return stored_name


def decrypt_file(file_record):
    path = UPLOAD_DIR / file_record.stored_name
    if not path.is_file():
        abort(404)
    try:
        return cipher.decrypt(path.read_bytes())
    except InvalidToken:
        app.logger.exception("File decryption failed")
        abort(500)


@app.route("/")
def index():
    if current_user():
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if len(username) < 3 or len(username) > 80:
            flash("Username must be between 3 and 80 characters.", "danger")
        elif len(password) < 10:
            flash("Password must contain at least 10 characters.", "danger")
        elif User.query.filter_by(username=username).first():
            flash("Username already exists.", "danger")
        else:
            user = User(
                username=username,
                password_hash=generate_password_hash(password),
                role="user",
            )
            db.session.add(user)
            db.session.commit()
            flash("Account created. Please log in.", "success")
            return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            session.clear()
            session["user_id"] = user.id
            session.permanent = True
            app.permanent_session_lifetime = timedelta(minutes=30)
            return redirect(url_for("dashboard"))

        flash("Invalid username or password.", "danger")

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("You have logged out.", "success")
    return redirect(url_for("login"))


@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    user = current_user()

    if request.method == "POST":
        uploaded = request.files.get("file")
        if not uploaded or not uploaded.filename:
            flash("Choose a file to upload.", "danger")
            return redirect(url_for("dashboard"))

        safe_name = secure_filename(uploaded.filename)
        if not safe_name:
            flash("Invalid filename.", "danger")
            return redirect(url_for("dashboard"))

        try:
            stored_name = encrypt_and_save(uploaded)
            record = StoredFile(
                original_name=safe_name,
                stored_name=stored_name,
                owner_id=user.id,
            )
            db.session.add(record)
            db.session.commit()
        except Exception:
            db.session.rollback()
            app.logger.exception("File upload failed")
            flash("Upload failed. Please try again.", "danger")
        else:
            flash("File encrypted and uploaded successfully.", "success")

        return redirect(url_for("dashboard"))

    if user.role == "admin":
        files = StoredFile.query.order_by(StoredFile.id.desc()).all()
    else:
        permitted_ids = db.session.query(FilePermission.file_id).filter_by(
            user_id=user.id
        )
        files = StoredFile.query.filter(
            db.or_(
                StoredFile.owner_id == user.id,
                StoredFile.id.in_(permitted_ids),
            )
        ).order_by(StoredFile.id.desc()).all()

    return render_template("dashboard.html", user=user, files=files)


@app.route("/download/<int:file_id>")
@login_required
def download(file_id):
    user = current_user()
    record = db.session.get(StoredFile, file_id)

    if not can_access_file(record, user):
        abort(404)

    content = decrypt_file(record)
    return send_file(
        BytesIO(content),
        as_attachment=True,
        download_name=record.original_name,
    )


@app.route("/share/<int:file_id>", methods=["POST"])
@login_required
def share_file(file_id):
    user = current_user()
    record = db.session.get(StoredFile, file_id)

    if not record or record.owner_id != user.id:
        abort(404)

    username = request.form.get("username", "").strip()
    recipient = User.query.filter_by(username=username).first()

    if not recipient:
        flash("Recipient not found.", "danger")
    elif recipient.id == user.id:
        flash("You already own this file.", "warning")
    else:
        existing = FilePermission.query.filter_by(
            file_id=record.id, user_id=recipient.id
        ).first()
        if not existing:
            db.session.add(
                FilePermission(file_id=record.id, user_id=recipient.id)
            )
            db.session.commit()
        flash("File access granted.", "success")

    return redirect(url_for("dashboard"))


@app.route("/create-link/<int:file_id>", methods=["POST"])
@login_required
def create_link(file_id):
    user = current_user()
    record = db.session.get(StoredFile, file_id)

    if not record or record.owner_id != user.id:
        abort(404)

    try:
        minutes = int(request.form.get("minutes", "10"))
    except ValueError:
        abort(400)

    if not 1 <= minutes <= 1440:
        abort(400)

    raw_token = secrets.token_urlsafe(32)
    token_hash = __import__("hashlib").sha256(
        raw_token.encode()
    ).hexdigest()

    expiry = datetime.now(timezone.utc) + timedelta(minutes=minutes)
    link = DownloadLink(
        token_hash=token_hash,
        file_id=record.id,
        created_by=user.id,
        expires_at=expiry,
        used=False,
    )
    db.session.add(link)
    db.session.commit()

    share_url = url_for("temporary_download", token=raw_token, _external=True)
    return render_template(
        "share_link.html", share_url=share_url, expires_at=expiry
    )


@app.route("/temporary/<token>")
def temporary_download(token):
    import hashlib

    token_hash = hashlib.sha256(token.encode()).hexdigest()
    link = DownloadLink.query.filter_by(token_hash=token_hash).first()

    if not link or link.used:
        abort(404)

    expiry = link.expires_at
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)

    if datetime.now(timezone.utc) >= expiry:
        abort(410)

    record = db.session.get(StoredFile, link.file_id)
    if not record:
        abort(404)

    # Consume the link before returning the decrypted file.
    link.used = True
    db.session.commit()

    content = decrypt_file(record)
    return send_file(
        BytesIO(content),
        as_attachment=True,
        download_name=record.original_name,
    )


@app.route("/admin")
@login_required
@admin_required
def admin():
    users = User.query.order_by(User.id.asc()).all()
    files = StoredFile.query.order_by(StoredFile.id.desc()).all()
    return render_template("admin.html", users=users, files=files)


@app.route("/admin/promote/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def promote_user(user_id):
    user = db.session.get(User, user_id)
    if not user:
        abort(404)
    if user.id == current_user().id:
        flash("You cannot change your own role here.", "warning")
    else:
        user.role = "admin"
        db.session.commit()
        flash("User promoted to admin.", "success")
    return redirect(url_for("admin"))


@app.errorhandler(403)
def forbidden(error):
    return "Forbidden: you do not have permission to access this resource.", 403


@app.errorhandler(404)
def not_found(error):
    return "File or page not found.", 404


@app.errorhandler(410)
def expired_link(error):
    return "This download link has expired.", 410


with app.app_context():
    db.create_all()

    # Bootstrap the first administrator from environment variables.
    admin_username = os.getenv("ADMIN_USERNAME")
    admin_password = os.getenv("ADMIN_PASSWORD")

    if admin_username and admin_password:
        existing_admin = User.query.filter_by(
            username=admin_username
        ).first()
        if not existing_admin:
            db.session.add(
                User(
                    username=admin_username,
                    password_hash=generate_password_hash(admin_password),
                    role="admin",
                )
            )
            db.session.commit()


if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG", "false").lower() == "true")
