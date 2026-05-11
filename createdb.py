import sqlite3

DB_PATH = "database.db"
conn = sqlite3.connect(DB_PATH)
c = conn.cursor()
c.execute("PRAGMA foreign_keys = ON")

for table in [
    "admin_audit_logs",
    "payments",
    "lesson_progress",
    "lessons",
    "cancellation_requests",
    "subscriptions",
    "courses",
    "plans",
    "users",
]:
    c.execute(f"DROP TABLE IF EXISTS {table}")

c.execute('''CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    status TEXT DEFAULT 'active',
    created_at TEXT DEFAULT (datetime('now'))
)''')

c.execute('''CREATE TABLE plans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    price REAL NOT NULL,
    billing_cycle TEXT NOT NULL,
    stripe_price_id TEXT DEFAULT '',
    status TEXT DEFAULT 'active',
    created_at TEXT DEFAULT (datetime('now'))
)''')

c.execute('''CREATE TABLE courses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    plan_id INTEGER NOT NULL,
    status TEXT DEFAULT 'draft',
    thumbnail_url TEXT DEFAULT '',
    level TEXT DEFAULT '',
    duration TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (plan_id) REFERENCES plans(id)
)''')

c.execute('''CREATE TABLE lessons (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    course_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    content TEXT DEFAULT '',
    video_url TEXT DEFAULT '',
    position INTEGER DEFAULT 0,
    status TEXT DEFAULT 'published',
    duration_minutes INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE
)''')

c.execute('''CREATE TABLE lesson_progress (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    lesson_id INTEGER NOT NULL,
    completed_at TEXT DEFAULT (datetime('now')),
    UNIQUE(user_id, lesson_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (lesson_id) REFERENCES lessons(id) ON DELETE CASCADE
)''')

c.execute('''CREATE TABLE subscriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    plan_id INTEGER NOT NULL,
    start_date TEXT NOT NULL,
    end_date TEXT NOT NULL,
    status TEXT DEFAULT 'active',
    stripe_customer_id TEXT DEFAULT '',
    stripe_subscription_id TEXT DEFAULT '',
    checkout_session_id TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (plan_id) REFERENCES plans(id)
)''')

c.execute('''CREATE TABLE payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    subscription_id INTEGER,
    stripe_invoice_id TEXT DEFAULT '',
    stripe_payment_intent_id TEXT DEFAULT '',
    amount REAL NOT NULL,
    currency TEXT DEFAULT 'PHP',
    status TEXT NOT NULL,
    paid_at TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (subscription_id) REFERENCES subscriptions(id)
)''')

c.execute('''CREATE TABLE cancellation_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subscription_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    reason TEXT DEFAULT '',
    cancel_mode TEXT DEFAULT 'period_end',
    status TEXT DEFAULT 'pending',
    created_at TEXT,
    processed_at TEXT,
    FOREIGN KEY (subscription_id) REFERENCES subscriptions(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
)''')

c.execute('''CREATE TABLE admin_audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_id INTEGER NOT NULL,
    action TEXT NOT NULL,
    target_type TEXT,
    target_id INTEGER,
    details TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (admin_id) REFERENCES users(id)
)''')

plans = [
    ("Starter", "Perfect for beginners. Access foundational courses to start your learning journey.", 299, "Monthly", "price_REPLACE_STARTER"),
    ("Professional", "For serious learners. Unlock intermediate and advanced courses with priority support.", 799, "Monthly", "price_REPLACE_PROFESSIONAL"),
    ("Enterprise", "Full access to every course. Best for teams and power learners who want it all.", 1499, "Monthly", "price_REPLACE_ENTERPRISE"),
]
c.executemany("INSERT INTO plans (name, description, price, billing_cycle, stripe_price_id) VALUES (?, ?, ?, ?, ?)", plans)

courses = [
    ("Introduction to Web Development", "Learn HTML, CSS, and JavaScript fundamentals from scratch.", 1, "published", "Beginner", "3 hours"),
    ("Python Programming Basics", "Master Python syntax, data structures, and problem-solving techniques.", 1, "published", "Beginner", "4 hours"),
    ("Database Design & SQL", "Design efficient databases and write powerful SQL queries.", 2, "published", "Intermediate", "5 hours"),
    ("Full-Stack Web Application", "Build complete web applications with modern frameworks and tools.", 2, "published", "Intermediate", "7 hours"),
    ("Cloud Computing & DevOps", "Deploy and manage applications in the cloud with CI/CD pipelines.", 3, "published", "Advanced", "6 hours"),
    ("Machine Learning Foundations", "Explore ML algorithms, model training, and real-world applications.", 3, "published", "Advanced", "6 hours"),
]
c.executemany("INSERT INTO courses (title, description, plan_id, status, level, duration) VALUES (?, ?, ?, ?, ?, ?)", courses)

sample_lessons = [
    (1, "Welcome to Web Development", "Overview of how websites work and what you will build.", "", 1, "published", 12),
    (1, "HTML Fundamentals", "Learn the core HTML tags used to structure web pages.", "", 2, "published", 25),
    (1, "CSS Basics", "Style pages with selectors, colors, spacing, and layout.", "", 3, "published", 30),
    (2, "Python Setup", "Install Python and prepare your coding environment.", "", 1, "published", 15),
    (2, "Variables and Data Types", "Understand strings, numbers, booleans, lists, and dictionaries.", "", 2, "published", 28),
    (2, "Control Flow", "Use if statements and loops to solve problems.", "", 3, "published", 32),
    (3, "Database Concepts", "Understand tables, rows, columns, keys, and relationships.", "", 1, "published", 25),
    (3, "SELECT Queries", "Read data using SELECT, WHERE, ORDER BY, and LIMIT.", "", 2, "published", 35),
    (4, "Full-Stack Architecture", "See how frontend, backend, database, and authentication fit together.", "", 1, "published", 30),
    (4, "Building CRUD Features", "Create, read, update, and delete records in a web app.", "", 2, "published", 45),
    (5, "Cloud Deployment Overview", "Learn the common steps for deploying web applications.", "", 1, "published", 30),
    (5, "CI/CD Basics", "Understand automated testing and deployment pipelines.", "", 2, "published", 35),
    (6, "What Is Machine Learning?", "Learn the difference between rules-based software and ML models.", "", 1, "published", 25),
    (6, "Training and Evaluation", "Understand datasets, model training, validation, and metrics.", "", 2, "published", 40),
]
c.executemany("""
    INSERT INTO lessons (course_id, title, content, video_url, position, status, duration_minutes)
    VALUES (?, ?, ?, ?, ?, ?, ?)
""", sample_lessons)

conn.commit()
conn.close()
print("Database initialized. Next: run create_admin.py, then replace Stripe price IDs in the admin panel.")
