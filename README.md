# Stored XSS Security Lab

Aplikasi simulasi keamanan web untuk penelitian Stored XSS dengan fitur:
- Rule-Based Detection Engine
- CSP Nonce Dinamis
- CSP Violation Report
- Dashboard Keamanan
- Modul Simulasi Akademik (Forum, Komentar, Pengumuman, Chat)

## 🚀 Quick Start

### Local Development

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Setup environment variables
cp .env.example .env
# Edit .env and fill in your database credentials

# Run migrations
flask db upgrade

# Run application
python run.py
```

Access at: http://127.0.0.1:5000

## 📋 Requirements

- Python 3.9+
- MySQL 5.7+ or MySQL 8.0+
- Flask 3.0+

## 🔧 Configuration

Edit `.env` file:

```env
SECRET_KEY=your-secret-key-here
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your-password
DB_NAME=stored_xss_security
DB_PORT=3306
```

## 📦 Deployment

Lihat [DEPLOYMENT.md](DEPLOYMENT.md) untuk panduan deployment ke Vercel + Aiven MySQL (gratis).

## 👥 User Roles

### Student
- Login via `/login-student`
- Input payload pada modul simulasi akademik
- Akses dashboard student

### Admin
- Login via `/login-admin`
- Monitor security engine
- Akses dashboard keamanan dan reports

## 📄 License

Project ini hanya untuk tujuan penelitian akademik.
