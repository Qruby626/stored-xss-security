import os
from dotenv import load_dotenv

load_dotenv()

basedir = os.path.abspath(os.path.dirname(__file__))


def _require_env(key: str, default=None):
    """
    Ambil nilai environment variable.
    Jika tidak ada dan tidak ada default, raise RuntimeError yang jelas.
    """
    val = os.environ.get(key, default)
    if val is None:
        raise RuntimeError(
            f"[Config Error] '{key}' tidak ditemukan pada file .env. "
            f"Salin .env.example menjadi .env dan isi nilainya."
        )
    return val


class Config:
    # ─── Security ────────────────────────────────────────────────────────────
    # SECRET_KEY HARUS ada di .env — tidak boleh ada fallback default
    SECRET_KEY: str = _require_env("SECRET_KEY")
    if not SECRET_KEY:
        raise RuntimeError(
            "[Config Error] SECRET_KEY tidak boleh kosong. "
            "Isi SECRET_KEY pada file .env dengan string acak yang panjang."
        )

    WTF_CSRF_ENABLED = True

    # ─── Database ─────────────────────────────────────────────────────────────
    # Untuk deployment Vercel + PlanetScale, gunakan DATABASE_URL
    # Untuk local development, gunakan DB_USER, DB_PASSWORD, DB_HOST, DB_PORT, DB_NAME
    DATABASE_URL = os.environ.get("DATABASE_URL")

    if DATABASE_URL:
        # Format PlanetScale: mysql://user:pass@host/db?ssl_accept=strict
        # Convert to SQLAlchemy format: mysql+pymysql://user:pass@host/db?ssl_ca=/etc/ssl/certs/ca-bundle.crt
        if DATABASE_URL.startswith("mysql://"):
            DATABASE_URL = DATABASE_URL.replace("mysql://", "mysql+pymysql://", 1)
        SQLALCHEMY_DATABASE_URI = DATABASE_URL
    else:
        # Fallback ke local MySQL untuk development
        DB_USER     = os.environ.get("DB_USER",     "root")
        DB_PASSWORD = os.environ.get("DB_PASSWORD", "")
        DB_HOST     = os.environ.get("DB_HOST",     "localhost")
        DB_PORT     = os.environ.get("DB_PORT",     "3306")
        DB_NAME     = os.environ.get("DB_NAME",     "stored_xss_security")

        SQLALCHEMY_DATABASE_URI = (
            f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
        )

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ─── CSP / Talisman ───────────────────────────────────────────────────────
    # FORCE_HTTPS = False karena aplikasi hanya digunakan di localhost (penelitian)
    FORCE_HTTPS     = False
    CSP_REPORT_ONLY = False
    CSP_REPORT_URI  = "/csp-report"

    # Maksimal jumlah laporan CSP yang ditampilkan di UI (default 200)
    # Bisa diubah via environment variable CSP_REPORTS_MAX
    try:
        CSP_REPORTS_MAX = int(os.environ.get("CSP_REPORTS_MAX", 200))
    except (TypeError, ValueError):
        CSP_REPORTS_MAX = 200

    # ─── Application ─────────────────────────────────────────────────────────
    ITEMS_PER_PAGE    = 20
    MAX_CONTENT_LENGTH = 2 * 1024 * 1024   # 2 MB upload limit

    # ─── Session Cookie (Penelitian) ─────────────────────────────────────────
    # HttpOnly dinonaktifkan agar simulasi pencurian cookie via document.cookie
    # dapat berhasil pada Skenario 1 (CSP OFF). Hanya untuk lingkungan localhost.
    SESSION_COOKIE_HTTPONLY = False

    # ─── XSS Detection Rules (Rule-Based Detection Engine) ───────────────────
    # Semua pattern digunakan dengan flag re.IGNORECASE pada xss_detector.py
    XSS_PATTERNS = [
        # ── Tag injection ──────────────────────────────────────────────────
        r"<script[\s\S]*?>",        # Opening script tag
        r"</script>",               # Closing script tag
        r"<img[\s\S]*?>",           # img tag (potential onerror injection)
        r"<svg[\s\S]*?>",           # SVG tag
        r"<iframe[\s\S]*?>",        # iframe tag

        # ── JavaScript URI & schemes ───────────────────────────────────────
        r"javascript\s*:",          # javascript: URI scheme
        r"data\s*:\s*text/html",    # data:text/html URI

        # ── Event handler attributes ───────────────────────────────────────
        r"on\w+\s*=",               # Generic event handler (onerror=, onload=, etc.)
        r"onerror\s*=",             # Specific: onerror
        r"onload\s*=",              # Specific: onload
        r"onclick\s*=",             # Specific: onclick
        r"onmouseover\s*=",         # Specific: onmouseover

        # ── Dangerous attributes ───────────────────────────────────────────
        r"srcdoc\s*=",              # iframe srcdoc execution

        # ── JavaScript functions / APIs ────────────────────────────────────
        r"alert\s*\(",              # alert()
        r"confirm\s*\(",            # confirm()
        r"prompt\s*\(",             # prompt()
        r"eval\s*\(",               # eval()
        r"fetch\s*\(",              # fetch() API
        r"setTimeout\s*\(",         # setTimeout()
        r"setInterval\s*\(",        # setInterval()
        r"XMLHttpRequest",          # AJAX / XHR

        # ── Obfuscation techniques ─────────────────────────────────────────
        r"String\.fromCharCode",    # Character-code obfuscation

        # ── Sensitive data access ──────────────────────────────────────────
        r"document\.cookie",        # Cookie theft
        r"document\.location",      # Document location manipulation
        r"document\.write",         # DOM write injection
        r"window\.location",        # Window location redirect
        r"location\.href",          # Location href redirect
        r"innerHTML",               # Direct DOM injection
        r"localStorage",            # LocalStorage access
        r"sessionStorage",          # SessionStorage access
    ]
