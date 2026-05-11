import os
import sqlite3
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash

load_dotenv()

admin_email = os.getenv("ADMIN_EMAIL")
admin_password = os.getenv("ADMIN_PASSWORD")

if not admin_email or not admin_password:
    raise ValueError("ADMIN_EMAIL and ADMIN_PASSWORD must be set in .env")

conn = sqlite3.connect("database.db")
c = conn.cursor()

c.execute("SELECT * FROM users WHERE email=?", (admin_email,))
existing = c.fetchone()

if existing:
    print("Admin already exists!")
else:
    hashed_password = generate_password_hash(admin_password)

    c.execute("""
        INSERT INTO users (name, email, password, role)
        VALUES (?, ?, ?, ?)
    """, ("Admin", admin_email, hashed_password, "admin"))

    conn.commit()
    print("Admin created successfully!")

conn.close()