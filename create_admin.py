import os
import sqlite3
import hashlib
import secrets
from dotenv import load_dotenv

try:
    from werkzeug.security import generate_password_hash
except Exception:
    def generate_password_hash(password):
        # Werkzeug-compatible PBKDF2 hash fallback for environments where requirements are not installed yet.
        method = "pbkdf2:sha256:1000000"
        salt = secrets.token_hex(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 1000000).hex()
        return f"{method}${salt}${digest}"

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))
admin_email = os.getenv("ADMIN_EMAIL", "admin@gmail.com")
admin_password = os.getenv("ADMIN_PASSWORD", "admin12345")
admin_name = os.getenv("ADMIN_NAME", "Admin")
conn = sqlite3.connect(os.getenv("DATABASE_PATH", "database.db"))
c = conn.cursor()
c.execute("SELECT * FROM users WHERE email=?", (admin_email,))
if c.fetchone():
    print("Admin already exists!")
else:
    c.execute("""
        INSERT INTO users (name, email, password, role, status, university, email_verified)
        VALUES (?, ?, ?, 'admin', 'active', '', 1)
    """, (admin_name, admin_email, generate_password_hash(admin_password)))
    conn.commit()
    print("Admin created successfully!")
conn.close()
