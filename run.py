"""Application entry point.

Untuk development: python run.py
Untuk production (Vercel): WSGI server akan import `app` dari file ini
"""
from app import create_app

app = create_app()

if __name__ == "__main__":
    # host tidak disetel ke 0.0.0.0 karena aplikasi ini
    # hanya digunakan di lingkungan localhost untuk penelitian.
    app.run(debug=True)
