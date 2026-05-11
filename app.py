import os
import hmac
import sqlite3
import secrets
from dotenv import load_dotenv
from datetime import datetime, timedelta
from functools import wraps

import stripe
from flask import Flask, request, render_template, redirect, session, flash, url_for, abort
from markupsafe import Markup, escape
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv() 

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-secret-change-me")

DB_PATH = os.getenv("DATABASE_PATH", "database.db")
stripe.api_key = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")


# =========================
# DB HELPERS
# =========================
def get_db():
    db_path = os.getenv("DATABASE_PATH", "database.db")
    conn = sqlite3.connect(db_path, timeout=10)
    conn.row_factory = sqlite3.Row

    # Helps reduce SQLite locking problems
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=10000")

    return conn


def log_admin_action(action, target_type=None, target_id=None, details=None, conn=None):
    """
    Logs admin actions safely.

    Important:
    If another route already has an open database connection,
    pass conn=conn to avoid SQLite database locked errors.
    """

    should_close = False

    if conn is None:
        conn = get_db()
        should_close = True

    try:
        conn.execute("""
            INSERT INTO admin_audit_logs (
                admin_id,
                action,
                target_type,
                target_id,
                details,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            session.get("user_id"),
            action,
            target_type,
            target_id,
            details,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))

        if should_close:
            conn.commit()

    except Exception as e:
        print("Audit log error:", e)

    finally:
        if should_close:
            conn.close()


# =========================
# SIMPLE CSRF PROTECTION
# =========================
def get_csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_urlsafe(32)
    return session["_csrf_token"]


@app.context_processor
def inject_helpers():
    def csrf_field():
        return Markup(f'<input type="hidden" name="csrf_token" value="{escape(get_csrf_token())}">')

    return {"csrf_token": get_csrf_token, "csrf_field": csrf_field}


@app.before_request
def protect_posts():
    if request.method != "POST":
        return
    if request.endpoint == "stripe_webhook":
        return
    sent = request.form.get("csrf_token", "")
    expected = session.get("_csrf_token", "")
    if not expected or not hmac.compare_digest(sent, expected):
        abort(400, "Invalid CSRF token")


# =========================
# AUTH DECORATORS
# =========================
def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/login")
        return func(*args, **kwargs)

    return wrapper


def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "user_id" not in session or session.get("role") != "admin":
            flash("Access denied", "danger")
            return redirect("/login")
        return func(*args, **kwargs)

    return wrapper


@app.before_request
def refresh_admin_badges():
    if session.get("role") == "admin":
        conn = get_db()
        pending = conn.execute("SELECT COUNT(*) FROM cancellation_requests WHERE status='pending'").fetchone()[0]
        failed = conn.execute("SELECT COUNT(*) FROM payments WHERE status='failed'").fetchone()[0]
        conn.close()
        session["pending_count"] = pending
        session["failed_payment_count"] = failed


# =========================
# SUBSCRIPTION HELPERS
# =========================
def auto_expire():
    conn = get_db()
    conn.execute(
        """
        UPDATE subscriptions
        SET status='expired'
        WHERE end_date < date('now') AND status='active'
        """
    )
    conn.commit()
    conn.close()


def get_active_subscription(conn, user_id):
    return conn.execute(
        """
        SELECT s.*, p.name as plan_name, p.price, p.billing_cycle
        FROM subscriptions s
        JOIN plans p ON s.plan_id = p.id
        WHERE s.user_id = ? AND s.status = 'active'
        ORDER BY s.id DESC LIMIT 1
        """,
        (user_id,),
    ).fetchone()


def user_can_access_course(conn, user_id, course_id):
    active_sub = get_active_subscription(conn, user_id)
    if not active_sub:
        return False, None, None

    course = conn.execute(
        """
        SELECT c.*, p.name as plan_name, p.price as plan_price
        FROM courses c
        JOIN plans p ON c.plan_id = p.id
        WHERE c.id = ? AND c.status='published'
        """,
        (course_id,),
    ).fetchone()

    if not course:
        return False, active_sub, None

    can_access = course["plan_price"] <= active_sub["price"]
    return can_access, active_sub, course


def calculate_end_date(start_dt, billing_cycle):
    cycle = (billing_cycle or "monthly").lower()
    if cycle == "yearly":
        try:
            return start_dt.replace(year=start_dt.year + 1)
        except ValueError:
            return start_dt + timedelta(days=365)
    if cycle == "quarterly":
        return start_dt + timedelta(days=90)
    return start_dt + timedelta(days=30)


# =========================
# AUTH ROUTES
# =========================
@app.route("/")
def home():
    return redirect("/dashboard" if session.get("user_id") else "/login")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        data = request.form
        if data["password"] != data["confirm_password"]:
            flash("Passwords do not match", "danger")
            return redirect("/register")

        hashed = generate_password_hash(data["password"])
        conn = get_db()
        try:
            conn.execute(
                "INSERT INTO users (name, email, password, role, status) VALUES (?, ?, ?, ?, 'active')",
                (data["name"].strip(), data["email"].strip().lower(), hashed, "user"),
            )
            conn.commit()
            flash("Account created! Please login.", "success")
            return redirect("/login")
        except sqlite3.IntegrityError:
            flash("Email already exists", "danger")
            return redirect("/register")
        finally:
            conn.close()

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        data = request.form
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE email=?", (data["email"].strip().lower(),)).fetchone()
        conn.close()

        if user and user["status"] != "active":
            flash("This account is disabled. Contact support.", "danger")
            return redirect("/login")

        if user and check_password_hash(user["password"], data["password"]):
            session.clear()
            session["user_id"] = user["id"]
            session["user_name"] = user["name"]
            session["role"] = user["role"]
            get_csrf_token()
            return redirect("/dashboard")

        flash("Invalid email or password", "danger")
        return redirect("/login")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


# =========================
# USER ROUTES
# =========================
@app.route("/dashboard")
@login_required
def dashboard():
    if session.get("role") == "admin":
        return redirect("/admin")

    auto_expire()
    conn = get_db()
    subscriptions = conn.execute(
        """
        SELECT s.id, p.name as plan_name, s.start_date, s.end_date, s.status, p.price, p.billing_cycle
        FROM subscriptions s
        JOIN plans p ON s.plan_id = p.id
        WHERE s.user_id = ?
        ORDER BY s.id DESC
        """,
        (session["user_id"],),
    ).fetchall()

    active_sub = get_active_subscription(conn, session["user_id"])
    course_count = 0
    if active_sub:
        course_count = conn.execute(
            """
            SELECT COUNT(*)
            FROM courses c
            JOIN plans p ON c.plan_id = p.id
            WHERE p.price <= ? AND c.status='published'
            """,
            (active_sub["price"],),
        ).fetchone()[0]

    pending_cancel = None
    if active_sub:
        pending_cancel = conn.execute(
            "SELECT * FROM cancellation_requests WHERE subscription_id=? AND status='pending'",
            (active_sub["id"],),
        ).fetchone()

    conn.close()
    return render_template(
        "dashboard.html",
        subscriptions=subscriptions,
        active_sub=active_sub,
        course_count=course_count,
        pending_cancel=pending_cancel,
    )


@app.route("/plans")
@login_required
def plans():
    conn = get_db()
    all_plans = conn.execute("SELECT * FROM plans WHERE status='active' ORDER BY price").fetchall()
    active_sub = get_active_subscription(conn, session["user_id"])
    conn.close()
    active_plan_id = active_sub["plan_id"] if active_sub else None
    return render_template("plans.html", plans=all_plans, active_plan_id=active_plan_id)


@app.route("/subscribe/<int:plan_id>")
@login_required
def subscribe(plan_id):
    conn = get_db()
    plan = conn.execute("SELECT * FROM plans WHERE id=? AND status='active'", (plan_id,)).fetchone()
    user = conn.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    conn.close()

    if not plan:
        flash("Plan not available", "danger")
        return redirect("/plans")
    if not plan["stripe_price_id"]:
        flash("This plan is not connected to Stripe yet.", "danger")
        return redirect("/plans")
    if not stripe.api_key:
        flash("Stripe secret key is not configured.", "danger")
        return redirect("/plans")

    try:
        checkout_session = stripe.checkout.Session.create(
            mode="subscription",
            customer_email=user["email"],
            success_url=url_for("checkout_success", _external=True) + "?session_id={CHECKOUT_SESSION_ID}",
            cancel_url=url_for("checkout_cancel", _external=True),
            line_items=[{"price": plan["stripe_price_id"], "quantity": 1}],
            metadata={"user_id": str(user["id"]), "plan_id": str(plan["id"])},
        )
        return redirect(checkout_session.url, code=303)
    except Exception as e:
        flash(f"Stripe error: {str(e)}", "danger")
        return redirect("/plans")


@app.route("/checkout/success")
@login_required
def checkout_success():
    session_id = request.args.get("session_id")

    if not session_id:
        flash("Missing checkout session.", "danger")
        return redirect("/plans")

    try:
        checkout_session = stripe.checkout.Session.retrieve(session_id)
    except Exception as e:
        flash(f"Unable to verify payment: {str(e)}", "danger")
        return redirect("/plans")

    payment_status = checkout_session.payment_status
    metadata = checkout_session.metadata or {}

    if payment_status != "paid":
        flash("Payment not completed.", "warning")
        return redirect("/plans")

    try:
        user_id = int(metadata["user_id"])
        plan_id = int(metadata["plan_id"])
    except Exception:
        flash("Missing payment metadata. Please contact support.", "danger")
        return redirect("/plans")

    stripe_subscription_id = checkout_session.subscription or ""
    stripe_customer_id = checkout_session.customer or ""
    checkout_session_id = checkout_session.id

    conn = get_db()

    existing = conn.execute("""
        SELECT *
        FROM subscriptions
        WHERE checkout_session_id=?
    """, (checkout_session_id,)).fetchone()

    payment_exists = conn.execute("""
        SELECT *
        FROM payments
        WHERE stripe_checkout_session_id=?
    """, (checkout_session_id,)).fetchone()

    if not existing:
        plan = conn.execute("""
            SELECT *
            FROM plans
            WHERE id=?
        """, (plan_id,)).fetchone()

        if not plan:
            conn.close()
            flash("Plan not found.", "danger")
            return redirect("/plans")

        from datetime import timedelta

        now_dt = datetime.now()
        start_date = now_dt.strftime("%Y-%m-%d")

        billing_cycle = plan["billing_cycle"].lower()

        if billing_cycle == "yearly":
            end_dt = now_dt.replace(year=now_dt.year + 1)
        elif billing_cycle == "quarterly":
            end_dt = now_dt + timedelta(days=90)
        else:
            end_dt = now_dt + timedelta(days=30)

        end_date = end_dt.strftime("%Y-%m-%d")

        conn.execute("""
            UPDATE subscriptions
            SET status='expired'
            WHERE user_id=? AND status='active'
        """, (user_id,))

        cursor = conn.execute("""
            INSERT INTO subscriptions (
                user_id,
                plan_id,
                start_date,
                end_date,
                status,
                stripe_customer_id,
                stripe_subscription_id,
                checkout_session_id
            )
            VALUES (?, ?, ?, ?, 'active', ?, ?, ?)
        """, (
            user_id,
            plan_id,
            start_date,
            end_date,
            stripe_customer_id,
            stripe_subscription_id,
            checkout_session_id
        ))

        subscription_id = cursor.lastrowid

    else:
        subscription_id = existing["id"]

        plan = conn.execute("""
            SELECT *
            FROM plans
            WHERE id=?
        """, (plan_id,)).fetchone()

        if not plan:
            conn.close()
            flash("Plan not found.", "danger")
            return redirect("/plans")

    if not payment_exists:
        conn.execute("""
            INSERT INTO payments (
                user_id,
                subscription_id,
                plan_id,
                amount,
                currency,
                status,
                source,
                stripe_checkout_session_id,
                paid_at
            )
            VALUES (?, ?, ?, ?, 'PHP', 'paid', 'checkout_success', ?, ?)
        """, (
            user_id,
            subscription_id,
            plan_id,
            plan["price"],
            checkout_session_id,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))

    conn.commit()
    conn.close()

    flash("Payment successful. Your subscription is now active.", "success")
    return redirect("/dashboard")


@app.route("/checkout/cancel")
@login_required
def checkout_cancel():
    flash("Checkout canceled.", "warning")
    return redirect("/plans")


def create_subscription_from_checkout(checkout_session):
    user_id = int(checkout_session["metadata"]["user_id"])
    plan_id = int(checkout_session["metadata"]["plan_id"])
    stripe_subscription_id = checkout_session.get("subscription", "")
    stripe_customer_id = checkout_session.get("customer", "")
    checkout_session_id = checkout_session["id"]

    conn = get_db()
    existing = conn.execute("SELECT * FROM subscriptions WHERE checkout_session_id=?", (checkout_session_id,)).fetchone()
    if existing:
        conn.close()
        return existing["id"]

    plan = conn.execute("SELECT * FROM plans WHERE id=?", (plan_id,)).fetchone()
    now_dt = datetime.now()
    start_date = now_dt.strftime("%Y-%m-%d")
    end_date = calculate_end_date(now_dt, plan["billing_cycle"]).strftime("%Y-%m-%d")

    conn.execute("UPDATE subscriptions SET status='expired' WHERE user_id=? AND status='active'", (user_id,))
    cur = conn.execute(
        """
        INSERT INTO subscriptions (
            user_id, plan_id, start_date, end_date, status,
            stripe_customer_id, stripe_subscription_id, checkout_session_id
        ) VALUES (?, ?, ?, ?, 'active', ?, ?, ?)
        """,
        (user_id, plan_id, start_date, end_date, stripe_customer_id, stripe_subscription_id, checkout_session_id),
    )
    sub_id = cur.lastrowid
    conn.execute(
        """
        INSERT INTO payments (user_id, subscription_id, stripe_invoice_id, stripe_payment_intent_id, amount, currency, status, paid_at)
        VALUES (?, ?, ?, ?, ?, 'PHP', 'paid', ?)
        """,
        (
            user_id,
            sub_id,
            checkout_session.get("invoice", ""),
            checkout_session.get("payment_intent", ""),
            float(plan["price"]),
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ),
    )
    conn.commit()
    conn.close()
    return sub_id


@app.route("/stripe/webhook", methods=["POST"])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get("Stripe-Signature")

    if STRIPE_WEBHOOK_SECRET:
        try:
            event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
        except Exception:
            return "Invalid webhook", 400
    else:
        event = request.get_json(force=True, silent=True) or {}

    event_type = event.get("type")
    obj = event.get("data", {}).get("object", {})

    if event_type == "checkout.session.completed" and obj.get("mode") == "subscription":
        create_subscription_from_checkout(obj)
    elif event_type == "invoice.payment_succeeded":
        record_invoice_payment(obj, "paid")
    elif event_type == "invoice.payment_failed":
        record_invoice_payment(obj, "failed")
    elif event_type == "customer.subscription.deleted":
        stripe_sub_id = obj.get("id")
        conn = get_db()
        conn.execute("UPDATE subscriptions SET status='canceled' WHERE stripe_subscription_id=?", (stripe_sub_id,))
        conn.commit()
        conn.close()

    return "ok", 200
def normalize_video_url(url):
    """
    Converts common YouTube URLs into iframe-safe embed URLs.

    Examples:
    https://www.youtube.com/watch?v=abc123
    becomes:
    https://www.youtube.com/embed/abc123

    https://youtu.be/abc123
    becomes:
    https://www.youtube.com/embed/abc123
    """

    if not url:
        return ""

    url = url.strip()

    # Already an embed URL
    if "youtube.com/embed/" in url:
        return url

    # Normal YouTube watch URL
    if "youtube.com/watch?v=" in url:
        video_id = url.split("watch?v=")[1].split("&")[0]
        return f"https://www.youtube.com/embed/{video_id}"

    # Short YouTube URL
    if "youtu.be/" in url:
        video_id = url.split("youtu.be/")[1].split("?")[0]
        return f"https://www.youtube.com/embed/{video_id}"

    # YouTube Shorts URL
    if "youtube.com/shorts/" in url:
        video_id = url.split("youtube.com/shorts/")[1].split("?")[0]
        return f"https://www.youtube.com/embed/{video_id}"

    # Leave other video URLs unchanged
    return url

def record_invoice_payment(invoice, status):
    stripe_sub_id = invoice.get("subscription", "")
    conn = get_db()
    sub = conn.execute("SELECT * FROM subscriptions WHERE stripe_subscription_id=?", (stripe_sub_id,)).fetchone()
    if sub:
        amount = (invoice.get("amount_paid") or invoice.get("amount_due") or 0) / 100
        paid_at = datetime.fromtimestamp(invoice.get("created", datetime.now().timestamp())).strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(
            """
            INSERT INTO payments (user_id, subscription_id, stripe_invoice_id, stripe_payment_intent_id, amount, currency, status, paid_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                sub["user_id"],
                sub["id"],
                invoice.get("id", ""),
                invoice.get("payment_intent", ""),
                amount,
                (invoice.get("currency") or "php").upper(),
                status,
                paid_at,
            ),
        )
        if status == "failed":
            conn.execute("UPDATE subscriptions SET status='past_due' WHERE id=?", (sub["id"],))
        conn.commit()
    conn.close()


@app.route("/my-courses")
@login_required
def my_courses():
    conn = get_db()
    active_sub = get_active_subscription(conn, session["user_id"])
    courses = []
    if active_sub:
        courses = conn.execute(
            """
            SELECT c.*, p.name as plan_name,
                   COUNT(DISTINCT l.id) as total_lessons,
                   COUNT(DISTINCT lp.lesson_id) as completed_lessons
            FROM courses c
            JOIN plans p ON c.plan_id = p.id
            LEFT JOIN lessons l ON l.course_id = c.id AND l.status='published'
            LEFT JOIN lesson_progress lp ON lp.lesson_id = l.id AND lp.user_id = ?
            WHERE p.price <= ? AND c.status='published'
            GROUP BY c.id
            ORDER BY p.price, c.title
            """,
            (session["user_id"], active_sub["price"]),
        ).fetchall()
    conn.close()
    return render_template("my_courses.html", courses=courses, active_sub=active_sub)


@app.route("/course/<int:course_id>")
@login_required
def course_detail(course_id):
    conn = get_db()
    can_access, active_sub, course = user_can_access_course(conn, session["user_id"], course_id)
    if not course:
        conn.close()
        flash("Course not found", "danger")
        return redirect("/my-courses")
    if not can_access:
        conn.close()
        flash("Subscribe to the required plan to access this course.", "warning")
        return redirect("/plans")

    lessons = conn.execute(
        """
        SELECT l.*, CASE WHEN lp.id IS NULL THEN 0 ELSE 1 END as is_completed
        FROM lessons l
        LEFT JOIN lesson_progress lp ON lp.lesson_id = l.id AND lp.user_id = ?
        WHERE l.course_id = ? AND l.status='published'
        ORDER BY l.position, l.id
        """,
        (session["user_id"], course_id),
    ).fetchall()
    total_lessons = len(lessons)
    completed_lessons = sum(1 for lesson in lessons if lesson["is_completed"])
    progress_percent = round((completed_lessons / total_lessons) * 100) if total_lessons else 0
    conn.close()
    return render_template(
        "course_detail.html",
        course=course,
        lessons=lessons,
        active_sub=active_sub,
        completed_lessons=completed_lessons,
        total_lessons=total_lessons,
        progress_percent=progress_percent,
    )


@app.route("/lesson/<int:lesson_id>")
@login_required
def lesson_detail(lesson_id):
    conn = get_db()
    lesson = conn.execute(
        """
        SELECT l.*, c.id as course_id, c.title as course_title, p.name as plan_name, p.price as plan_price
        FROM lessons l
        JOIN courses c ON l.course_id = c.id
        JOIN plans p ON c.plan_id = p.id
        WHERE l.id = ? AND l.status='published' AND c.status='published'
        """,
        (lesson_id,),
    ).fetchone()
    if not lesson:
        conn.close()
        flash("Lesson not found", "danger")
        return redirect("/my-courses")

    can_access, active_sub, course = user_can_access_course(conn, session["user_id"], lesson["course_id"])
    if not can_access:
        conn.close()
        flash("Subscribe to the required plan to access this lesson.", "warning")
        return redirect("/plans")

    progress = conn.execute("SELECT * FROM lesson_progress WHERE user_id=? AND lesson_id=?", (session["user_id"], lesson_id)).fetchone()
    previous_lesson = conn.execute(
        """
        SELECT id, title FROM lessons
        WHERE course_id=? AND status='published' AND (position < ? OR (position = ? AND id < ?))
        ORDER BY position DESC, id DESC LIMIT 1
        """,
        (lesson["course_id"], lesson["position"], lesson["position"], lesson_id),
    ).fetchone()
    next_lesson = conn.execute(
        """
        SELECT id, title FROM lessons
        WHERE course_id=? AND status='published' AND (position > ? OR (position = ? AND id > ?))
        ORDER BY position ASC, id ASC LIMIT 1
        """,
        (lesson["course_id"], lesson["position"], lesson["position"], lesson_id),
    ).fetchone()
    conn.close()
    return render_template("lesson_detail.html", lesson=lesson, course=course, progress=progress, previous_lesson=previous_lesson, next_lesson=next_lesson)


@app.route("/lesson/<int:lesson_id>/complete", methods=["POST"])
@login_required
def complete_lesson(lesson_id):
    conn = get_db()
    lesson = conn.execute("SELECT * FROM lessons WHERE id=? AND status='published'", (lesson_id,)).fetchone()
    if not lesson:
        conn.close()
        flash("Lesson not found", "danger")
        return redirect("/my-courses")
    can_access, active_sub, course = user_can_access_course(conn, session["user_id"], lesson["course_id"])
    if not can_access:
        conn.close()
        flash("You do not have access to this lesson.", "danger")
        return redirect("/plans")
    conn.execute(
        "INSERT OR IGNORE INTO lesson_progress (user_id, lesson_id, completed_at) VALUES (?, ?, ?)",
        (session["user_id"], lesson_id, datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
    )
    conn.commit()
    conn.close()
    flash("Lesson marked as completed", "success")
    return redirect(request.form.get("next") or url_for("lesson_detail", lesson_id=lesson_id))


@app.route("/request-cancellation/<int:sub_id>", methods=["POST"])
@login_required
def request_cancellation(sub_id):
    conn = get_db()
    sub = conn.execute("SELECT * FROM subscriptions WHERE id=? AND user_id=? AND status='active'", (sub_id, session["user_id"])).fetchone()
    if not sub:
        flash("Invalid subscription", "danger")
        conn.close()
        return redirect("/dashboard")
    existing = conn.execute("SELECT * FROM cancellation_requests WHERE subscription_id=? AND status='pending'", (sub_id,)).fetchone()
    if existing:
        flash("You already have a pending cancellation request", "warning")
        conn.close()
        return redirect("/cancellation-status")
    conn.execute(
        """
        INSERT INTO cancellation_requests (subscription_id, user_id, reason, cancel_mode, status, created_at)
        VALUES (?, ?, ?, ?, 'pending', ?)
        """,
        (
            sub_id,
            session["user_id"],
            request.form.get("reason", ""),
            request.form.get("cancel_mode", "period_end"),
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ),
    )
    conn.commit()
    conn.close()
    flash("Cancellation request submitted", "success")
    return redirect("/cancellation-status")


@app.route("/cancellation-status")
@login_required
def cancellation_status():
    conn = get_db()
    requests = conn.execute(
        """
        SELECT cr.*, p.name as plan_name, s.start_date, s.end_date
        FROM cancellation_requests cr
        JOIN subscriptions s ON cr.subscription_id = s.id
        JOIN plans p ON s.plan_id = p.id
        WHERE cr.user_id = ?
        ORDER BY cr.created_at DESC
        """,
        (session["user_id"],),
    ).fetchall()
    conn.close()
    return render_template("cancellation_status.html", requests=requests)


# =========================
# ADMIN ROUTES
# =========================
@app.route("/admin")
@admin_required
def admin():
    auto_expire()
    conn = get_db()
    total_users = conn.execute("SELECT COUNT(*) FROM users WHERE role='user'").fetchone()[0]
    active_subs = conn.execute("SELECT COUNT(*) FROM subscriptions WHERE status='active'").fetchone()[0]
    pending_cancellations = conn.execute("SELECT COUNT(*) FROM cancellation_requests WHERE status='pending'").fetchone()[0]
    total_courses = conn.execute("SELECT COUNT(*) FROM courses").fetchone()[0]
    failed_payments = conn.execute("SELECT COUNT(*) FROM payments WHERE status='failed'").fetchone()[0]
    revenue = conn.execute(
        "SELECT COALESCE(SUM(amount), 0) FROM payments WHERE status='paid' AND paid_at >= date('now', 'start of month')"
    ).fetchone()[0]
    recent_subs = conn.execute(
        """
        SELECT s.id, u.name as user_name, p.name as plan_name, s.status, s.start_date, s.end_date
        FROM subscriptions s
        JOIN users u ON s.user_id = u.id
        JOIN plans p ON s.plan_id = p.id
        ORDER BY s.id DESC LIMIT 10
        """
    ).fetchall()
    plans = conn.execute("SELECT * FROM plans ORDER BY price").fetchall()
    recent_logs = conn.execute(
        """
        SELECT l.*, u.name as admin_name
        FROM admin_audit_logs l
        JOIN users u ON l.admin_id = u.id
        ORDER BY l.id DESC LIMIT 8
        """
    ).fetchall()
    conn.close()
    return render_template(
        "admin.html",
        total_users=total_users,
        active_subs=active_subs,
        pending_cancellations=pending_cancellations,
        total_courses=total_courses,
        failed_payments=failed_payments,
        revenue=revenue,
        recent_subs=recent_subs,
        plans=plans,
        recent_logs=recent_logs,
    )


@app.route("/admin/create_plan", methods=["POST"])
@admin_required
def create_plan():
    data = request.form
    conn = get_db()
    cur = conn.execute(
        """
        INSERT INTO plans (name, description, price, billing_cycle, stripe_price_id, status)
        VALUES (?, ?, ?, ?, ?, 'active')
        """,
        (data["name"].strip(), data.get("description", ""), data["price"], data["billing_cycle"], data.get("stripe_price_id", "").strip()),
    )
    conn.commit()
    conn.close()
    log_admin_action("created plan", "plan", cur.lastrowid, data["name"])
    flash("Plan created successfully", "success")
    return redirect("/admin")


@app.route("/admin/edit_plan/<int:plan_id>", methods=["GET", "POST"])
@admin_required
def edit_plan(plan_id):
    conn = get_db()
    if request.method == "POST":
        data = request.form
        conn.execute(
            "UPDATE plans SET name=?, description=?, price=?, billing_cycle=?, stripe_price_id=? WHERE id=?",
            (data["name"].strip(), data.get("description", ""), data["price"], data["billing_cycle"], data.get("stripe_price_id", "").strip(), plan_id),
        )
        conn.commit()
        conn.close()
        log_admin_action("updated plan", "plan", plan_id, data["name"])
        flash("Plan updated successfully", "success")
        return redirect("/admin")
    plan = conn.execute("SELECT * FROM plans WHERE id=?", (plan_id,)).fetchone()
    conn.close()
    if not plan:
        flash("Plan not found", "danger")
        return redirect("/admin")
    return render_template("admin_edit_plan.html", plan=plan)


@app.route("/admin/toggle_plan/<int:plan_id>", methods=["POST"])
@admin_required
def toggle_plan(plan_id):
    conn = get_db()
    plan = conn.execute("SELECT status FROM plans WHERE id=?", (plan_id,)).fetchone()
    if plan:
        new_status = "inactive" if plan["status"] == "active" else "active"
        conn.execute("UPDATE plans SET status=? WHERE id=?", (new_status, plan_id))
        conn.commit()
        log_admin_action("toggled plan", "plan", plan_id, new_status)
        flash(f"Plan {'activated' if new_status == 'active' else 'deactivated'}", "success")
    conn.close()
    return redirect("/admin")


@app.route("/admin/delete_plan/<int:plan_id>", methods=["POST"])
@admin_required
def delete_plan(plan_id):
    conn = get_db()
    in_use = conn.execute("SELECT COUNT(*) FROM subscriptions WHERE plan_id=?", (plan_id,)).fetchone()[0]
    if in_use:
        flash("Cannot delete a plan with existing subscriptions. Deactivate it instead.", "warning")
    else:
        conn.execute("DELETE FROM plans WHERE id=?", (plan_id,))
        conn.commit()
        log_admin_action("deleted plan", "plan", plan_id)
        flash("Plan deleted", "success")
    conn.close()
    return redirect("/admin")


@app.route("/admin/users")
@admin_required
def admin_users():
    q = request.args.get("q", "").strip()
    status = request.args.get("status", "")
    conn = get_db()
    sql = """
        SELECT u.*, 
               (SELECT COUNT(*) FROM subscriptions WHERE user_id=u.id AND status='active') as active_subs,
               (SELECT p.name FROM subscriptions s JOIN plans p ON s.plan_id=p.id WHERE s.user_id=u.id AND s.status='active' ORDER BY s.id DESC LIMIT 1) as current_plan
        FROM users u
        WHERE u.role='user'
    """
    params = []
    if q:
        sql += " AND (u.name LIKE ? OR u.email LIKE ?)"
        params.extend([f"%{q}%", f"%{q}%"])
    if status:
        sql += " AND u.status=?"
        params.append(status)
    sql += " ORDER BY u.id DESC"
    users = conn.execute(sql, params).fetchall()
    conn.close()
    return render_template("admin_users.html", users=users, q=q, status=status)


@app.route("/admin/user/<int:user_id>")
@admin_required
def admin_user_detail(user_id):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        conn.close()
        flash("User not found", "danger")
        return redirect("/admin/users")
    subs = conn.execute(
        """
        SELECT s.*, p.name as plan_name, p.price, p.billing_cycle
        FROM subscriptions s JOIN plans p ON s.plan_id=p.id
        WHERE s.user_id=? ORDER BY s.id DESC
        """,
        (user_id,),
    ).fetchall()
    progress = conn.execute(
        """
        SELECT c.id, c.title, COUNT(DISTINCT l.id) total_lessons, COUNT(DISTINCT lp.lesson_id) completed_lessons
        FROM courses c
        LEFT JOIN lessons l ON l.course_id=c.id
        LEFT JOIN lesson_progress lp ON lp.lesson_id=l.id AND lp.user_id=?
        GROUP BY c.id ORDER BY c.title
        """,
        (user_id,),
    ).fetchall()
    payments = conn.execute("SELECT * FROM payments WHERE user_id=? ORDER BY id DESC", (user_id,)).fetchall()
    plans = conn.execute("SELECT * FROM plans WHERE status='active' ORDER BY price").fetchall()
    conn.close()
    return render_template("admin_user_detail.html", user=user, subs=subs, progress=progress, payments=payments, plans=plans)


@app.route("/admin/user/<int:user_id>/toggle_status", methods=["POST"])
@admin_required
def admin_toggle_user_status(user_id):
    conn = get_db()
    user = conn.execute("SELECT status FROM users WHERE id=? AND role='user'", (user_id,)).fetchone()
    if user:
        new_status = "disabled" if user["status"] == "active" else "active"
        conn.execute("UPDATE users SET status=? WHERE id=?", (new_status, user_id))
        conn.commit()
        log_admin_action("changed user status", "user", user_id, new_status)
        flash("User status updated", "success")
    conn.close()
    return redirect(url_for("admin_user_detail", user_id=user_id))


@app.route("/admin/user/<int:user_id>/assign_plan", methods=["POST"])
@admin_required
def admin_assign_plan(user_id):
    plan_id = request.form.get("plan_id")
    days = int(request.form.get("days", 30))
    conn = get_db()
    plan = conn.execute("SELECT * FROM plans WHERE id=?", (plan_id,)).fetchone()
    if not plan:
        flash("Invalid plan", "danger")
        conn.close()
        return redirect(url_for("admin_user_detail", user_id=user_id))
    start = datetime.now()
    end = start + timedelta(days=days)
    conn.execute("UPDATE subscriptions SET status='expired' WHERE user_id=? AND status='active'", (user_id,))
    conn.execute(
        """
        INSERT INTO subscriptions (user_id, plan_id, start_date, end_date, status)
        VALUES (?, ?, ?, ?, 'active')
        """,
        (user_id, plan_id, start.strftime("%Y-%m-%d"), end.strftime("%Y-%m-%d")),
    )
    conn.commit()
    conn.close()
    log_admin_action("assigned manual plan", "user", user_id, f"plan {plan_id}, {days} days")
    flash("Manual subscription assigned", "success")
    return redirect(url_for("admin_user_detail", user_id=user_id))


@app.route("/admin/subscriptions")
@admin_required
def admin_subscriptions():
    q = request.args.get("q", "").strip()
    status = request.args.get("status", "")
    conn = get_db()
    sql = """
        SELECT s.*, u.name as user_name, u.email, p.name as plan_name, p.price, p.billing_cycle
        FROM subscriptions s
        JOIN users u ON s.user_id=u.id
        JOIN plans p ON s.plan_id=p.id
        WHERE 1=1
    """
    params = []
    if q:
        sql += " AND (u.name LIKE ? OR u.email LIKE ? OR p.name LIKE ? OR s.stripe_subscription_id LIKE ?)"
        params.extend([f"%{q}%", f"%{q}%", f"%{q}%", f"%{q}%"])
    if status:
        sql += " AND s.status=?"
        params.append(status)
    sql += " ORDER BY s.id DESC"
    subscriptions = conn.execute(sql, params).fetchall()
    plans = conn.execute("SELECT * FROM plans WHERE status='active' ORDER BY price").fetchall()
    conn.close()
    return render_template("admin_subscriptions.html", subscriptions=subscriptions, plans=plans, q=q, status=status)


@app.route("/admin/subscription/<int:sub_id>/cancel", methods=["POST"])
@admin_required
def admin_cancel_subscription(sub_id):
    mode = request.form.get("mode", "period_end")
    conn = get_db()
    sub = conn.execute("SELECT * FROM subscriptions WHERE id=?", (sub_id,)).fetchone()
    if not sub:
        conn.close()
        flash("Subscription not found", "danger")
        return redirect("/admin/subscriptions")

    new_status = "canceling" if mode == "period_end" else "canceled"
    conn.execute("UPDATE subscriptions SET status=? WHERE id=?", (new_status, sub_id))
    conn.commit()
    conn.close()

    if sub["stripe_subscription_id"] and stripe.api_key:
        try:
            if mode == "period_end":
                stripe.Subscription.modify(sub["stripe_subscription_id"], cancel_at_period_end=True)
            else:
                stripe.Subscription.delete(sub["stripe_subscription_id"])
        except Exception as e:
            flash(f"Local status updated, but Stripe sync failed: {str(e)}", "warning")

    log_admin_action("canceled subscription", "subscription", sub_id, mode)
    flash("Subscription cancellation processed", "success")
    return redirect("/admin/subscriptions")


@app.route("/admin/subscription/<int:sub_id>/extend", methods=["POST"])
@admin_required
def admin_extend_subscription(sub_id):
    days = int(request.form.get("days", 30))
    conn = get_db()
    sub = conn.execute("SELECT * FROM subscriptions WHERE id=?", (sub_id,)).fetchone()
    if sub:
        base = datetime.strptime(sub["end_date"], "%Y-%m-%d") if sub["end_date"] else datetime.now()
        new_end = max(base, datetime.now()) + timedelta(days=days)
        conn.execute("UPDATE subscriptions SET end_date=?, status='active' WHERE id=?", (new_end.strftime("%Y-%m-%d"), sub_id))
        conn.commit()
        log_admin_action("extended subscription", "subscription", sub_id, f"{days} days")
        flash("Subscription extended", "success")
    conn.close()
    return redirect("/admin/subscriptions")


@app.route("/admin/subscription/<int:sub_id>/change_plan", methods=["POST"])
@admin_required
def admin_change_subscription_plan(sub_id):
    plan_id = request.form.get("plan_id")
    conn = get_db()
    conn.execute("UPDATE subscriptions SET plan_id=? WHERE id=?", (plan_id, sub_id))
    conn.commit()
    conn.close()
    log_admin_action("changed subscription plan", "subscription", sub_id, f"plan {plan_id}")
    flash("Subscription plan changed locally", "success")
    return redirect("/admin/subscriptions")


@app.route("/admin/payments")
@admin_required
def admin_payments():
    q = request.args.get("q", "").strip()
    status = request.args.get("status", "")
    conn = get_db()
    sql = """
        SELECT pay.*, u.name as user_name, u.email, p.name as plan_name
        FROM payments pay
        JOIN users u ON pay.user_id=u.id
        LEFT JOIN subscriptions s ON pay.subscription_id=s.id
        LEFT JOIN plans p ON s.plan_id=p.id
        WHERE 1=1
    """
    params = []
    if q:
        sql += " AND (u.name LIKE ? OR u.email LIKE ? OR pay.stripe_invoice_id LIKE ?)"
        params.extend([f"%{q}%", f"%{q}%", f"%{q}%"])
    if status:
        sql += " AND pay.status=?"
        params.append(status)
    sql += " ORDER BY pay.id DESC"
    payments = conn.execute(sql, params).fetchall()
    conn.close()
    return render_template("admin_payments.html", payments=payments, q=q, status=status)


@app.route("/admin/courses")
@admin_required
def admin_courses():
    conn = get_db()
    courses = conn.execute(
        """
        SELECT c.*, p.name as plan_name,
               COUNT(DISTINCT l.id) as lesson_count
        FROM courses c
        JOIN plans p ON c.plan_id = p.id
        LEFT JOIN lessons l ON l.course_id=c.id
        GROUP BY c.id
        ORDER BY p.price, c.title
        """
    ).fetchall()
    plans = conn.execute("SELECT * FROM plans WHERE status='active' ORDER BY price").fetchall()
    conn.close()
    return render_template("admin_courses.html", courses=courses, plans=plans)


@app.route("/admin/create_course", methods=["POST"])
@admin_required
def create_course():
    data = request.form
    conn = get_db()
    cur = conn.execute(
        """
        INSERT INTO courses (title, description, plan_id, status, thumbnail_url, level, duration)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            data["title"].strip(),
            data.get("description", ""),
            data["plan_id"],
            data.get("status", "draft"),
            data.get("thumbnail_url", ""),
            data.get("level", ""),
            data.get("duration", ""),
        ),
    )
    conn.commit()
    conn.close()
    log_admin_action("created course", "course", cur.lastrowid, data["title"])
    flash("Course added successfully", "success")
    return redirect("/admin/courses")


@app.route("/admin/edit_course/<int:course_id>", methods=["POST"])
@admin_required
def edit_course(course_id):
    data = request.form
    conn = get_db()
    conn.execute(
        """
        UPDATE courses SET title=?, description=?, plan_id=?, status=?, thumbnail_url=?, level=?, duration=? WHERE id=?
        """,
        (
            data["title"].strip(),
            data.get("description", ""),
            data["plan_id"],
            data.get("status", "draft"),
            data.get("thumbnail_url", ""),
            data.get("level", ""),
            data.get("duration", ""),
            course_id,
        ),
    )
    conn.commit()
    conn.close()
    log_admin_action("updated course", "course", course_id, data["title"])
    flash("Course updated", "success")
    return redirect("/admin/courses")


@app.route("/admin/delete_course/<int:course_id>", methods=["POST"])
@admin_required
def delete_course(course_id):
    conn = get_db()
    conn.execute("DELETE FROM courses WHERE id=?", (course_id,))
    conn.commit()
    conn.close()
    log_admin_action("deleted course", "course", course_id)
    flash("Course deleted", "success")
    return redirect("/admin/courses")


@app.route("/admin/course/<int:course_id>/lessons")
@admin_required
def admin_course_lessons(course_id):
    conn = get_db()
    course = conn.execute(
        """
        SELECT c.*, p.name as plan_name
        FROM courses c JOIN plans p ON c.plan_id = p.id
        WHERE c.id = ?
        """,
        (course_id,),
    ).fetchone()
    if not course:
        conn.close()
        flash("Course not found", "danger")
        return redirect("/admin/courses")
    lessons = conn.execute("SELECT * FROM lessons WHERE course_id=? ORDER BY position, id", (course_id,)).fetchall()
    conn.close()
    return render_template("admin_course_lessons.html", course=course, lessons=lessons)


@app.route("/admin/course/<int:course_id>/lessons/create", methods=["POST"])
@admin_required
def admin_create_lesson(course_id):
    title = request.form.get("title", "").strip()
    content = request.form.get("content", "").strip()
    video_url = normalize_video_url(request.form.get("video_url", ""))
    status = request.form.get("status", "published").strip()

    try:
        position = int(request.form.get("position", 0))
    except Exception:
        position = 0

    try:
        duration_minutes = int(request.form.get("duration_minutes", 0) or 0)
    except Exception:
        duration_minutes = 0

    if not title:
        flash("Lesson title is required.", "danger")
        return redirect(url_for("admin_course_lessons", course_id=course_id))

    conn = get_db()

    course = conn.execute("""
        SELECT *
        FROM courses
        WHERE id = ?
    """, (course_id,)).fetchone()

    if not course:
        conn.close()
        flash("Course not found.", "danger")
        return redirect("/admin/courses")

    try:
        conn.execute("""
            INSERT INTO lessons (
                course_id,
                title,
                content,
                video_url,
                position,
                status,
                duration_minutes
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            course_id,
            title,
            content,
            video_url,
            position,
            status,
            duration_minutes
        ))

        log_admin_action(
            "created lesson",
            "course",
            course_id,
            title,
            conn=conn
        )

        conn.commit()
        flash("Lesson added successfully.", "success")

    except Exception as e:
        conn.rollback()
        flash(f"Could not add lesson: {str(e)}", "danger")

    conn.close()

    return redirect(url_for("admin_course_lessons", course_id=course_id))


@app.route("/admin/lesson/<int:lesson_id>/edit", methods=["POST"])
@admin_required
def admin_edit_lesson(lesson_id):
    title = request.form.get("title", "").strip()
    content = request.form.get("content", "").strip()
    video_url = normalize_video_url(request.form.get("video_url", ""))
    status = request.form.get("status", "published").strip()

    try:
        position = int(request.form.get("position", 0))
    except Exception:
        position = 0

    try:
        duration_minutes = int(request.form.get("duration_minutes", 0) or 0)
    except Exception:
        duration_minutes = 0

    if not title:
        flash("Lesson title is required.", "danger")
        return redirect("/admin/courses")

    conn = get_db()

    lesson = conn.execute("""
        SELECT *
        FROM lessons
        WHERE id = ?
    """, (lesson_id,)).fetchone()

    if not lesson:
        conn.close()
        flash("Lesson not found.", "danger")
        return redirect("/admin/courses")

    try:
        conn.execute("""
            UPDATE lessons
            SET title = ?,
                content = ?,
                video_url = ?,
                position = ?,
                status = ?,
                duration_minutes = ?
            WHERE id = ?
        """, (
            title,
            content,
            video_url,
            position,
            status,
            duration_minutes,
            lesson_id
        ))

        log_admin_action(
            "updated lesson",
            "lesson",
            lesson_id,
            title,
            conn=conn
        )

        conn.commit()
        flash("Lesson updated successfully.", "success")

    except Exception as e:
        conn.rollback()
        flash(f"Could not update lesson: {str(e)}", "danger")

    course_id = lesson["course_id"]
    conn.close()

    return redirect(url_for("admin_course_lessons", course_id=course_id))


@app.route("/admin/lesson/<int:lesson_id>/delete", methods=["POST"])
@admin_required
def admin_delete_lesson(lesson_id):
    conn = get_db()
    lesson = conn.execute("SELECT * FROM lessons WHERE id=?", (lesson_id,)).fetchone()
    if not lesson:
        conn.close()
        flash("Lesson not found", "danger")
        return redirect("/admin/courses")
    course_id = lesson["course_id"]
    conn.execute("DELETE FROM lesson_progress WHERE lesson_id=?", (lesson_id,))
    conn.execute("DELETE FROM lessons WHERE id=?", (lesson_id,))
    conn.commit()
    conn.close()
    log_admin_action("deleted lesson", "lesson", lesson_id)
    flash("Lesson deleted", "success")
    return redirect(url_for("admin_course_lessons", course_id=course_id))


@app.route("/admin/cancellations")
@admin_required
def admin_cancellations():
    conn = get_db()
    requests = conn.execute(
        """
        SELECT cr.*, u.name as user_name, u.email, p.name as plan_name, s.start_date, s.end_date
        FROM cancellation_requests cr
        JOIN users u ON cr.user_id = u.id
        JOIN subscriptions s ON cr.subscription_id = s.id
        JOIN plans p ON s.plan_id = p.id
        ORDER BY (cr.status = 'pending') DESC, cr.created_at DESC
        """
    ).fetchall()
    conn.close()
    return render_template("admin_cancellations.html", requests=requests)


@app.route("/admin/process_cancellation/<int:req_id>", methods=["POST"])
@admin_required
def process_cancellation(req_id):
    action = request.form.get("action")
    cancel_mode = request.form.get("cancel_mode", "period_end")

    conn = get_db()

    cr = conn.execute("""
        SELECT cr.*,
               s.stripe_subscription_id,
               s.id as subscription_id
        FROM cancellation_requests cr
        JOIN subscriptions s ON cr.subscription_id = s.id
        WHERE cr.id=?
    """, (req_id,)).fetchone()

    if not cr:
        conn.close()
        flash("Cancellation request not found.", "danger")
        return redirect("/admin/cancellations")

    if cr["status"] != "pending":
        conn.close()
        flash("This request has already been processed.", "warning")
        return redirect("/admin/cancellations")

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if action == "approve":
        try:
            conn.execute("""
                UPDATE cancellation_requests
                SET status='approved',
                    processed_at=?,
                    cancel_mode=?
                WHERE id=?
            """, (now, cancel_mode, req_id))

            if cancel_mode == "immediate":
                conn.execute("""
                    UPDATE subscriptions
                    SET status='canceled'
                    WHERE id=?
                """, (cr["subscription_id"],))
            else:
                conn.execute("""
                    UPDATE subscriptions
                    SET status='canceling'
                    WHERE id=?
                """, (cr["subscription_id"],))

            log_admin_action(
                "approved cancellation",
                "cancellation_request",
                req_id,
                cancel_mode,
                conn=conn
            )

            conn.commit()

        except Exception as e:
            conn.rollback()
            conn.close()
            flash(f"Database error while approving cancellation: {str(e)}", "danger")
            return redirect("/admin/cancellations")

        conn.close()

        # Do Stripe call AFTER database commit to avoid SQLite locking
        if cr["stripe_subscription_id"]:
            try:
                if cancel_mode == "immediate":
                    stripe.Subscription.delete(cr["stripe_subscription_id"])
                else:
                    stripe.Subscription.modify(
                        cr["stripe_subscription_id"],
                        cancel_at_period_end=True
                    )
            except Exception as e:
                flash(
                    f"Cancellation approved locally, but Stripe sync failed: {str(e)}",
                    "warning"
                )
                return redirect("/admin/cancellations")

        flash("Cancellation approved successfully.", "success")
        return redirect("/admin/cancellations")

    elif action == "reject":
        try:
            conn.execute("""
                UPDATE cancellation_requests
                SET status='rejected',
                    processed_at=?
                WHERE id=?
            """, (now, req_id))

            log_admin_action(
                "rejected cancellation",
                "cancellation_request",
                req_id,
                "",
                conn=conn
            )

            conn.commit()

        except Exception as e:
            conn.rollback()
            conn.close()
            flash(f"Database error while rejecting cancellation: {str(e)}", "danger")
            return redirect("/admin/cancellations")

        conn.close()

        flash("Cancellation rejected.", "info")
        return redirect("/admin/cancellations")

    conn.close()
    flash("Invalid cancellation action.", "danger")
    return redirect("/admin/cancellations")


@app.route("/admin/progress")
@admin_required
def admin_progress():
    conn = get_db()
    rows = conn.execute(
        """
        SELECT u.id as user_id, u.name, u.email, c.id as course_id, c.title,
               COUNT(DISTINCT l.id) as total_lessons,
               COUNT(DISTINCT lp.lesson_id) as completed_lessons
        FROM users u
        CROSS JOIN courses c
        LEFT JOIN lessons l ON l.course_id=c.id AND l.status='published'
        LEFT JOIN lesson_progress lp ON lp.lesson_id=l.id AND lp.user_id=u.id
        WHERE u.role='user' AND c.status='published'
        GROUP BY u.id, c.id
        HAVING completed_lessons > 0
        ORDER BY u.name, c.title
        """
    ).fetchall()
    conn.close()
    return render_template("admin_progress.html", rows=rows)


@app.route("/admin/reports")
@admin_required
def admin_reports():
    conn = get_db()
    total_users = conn.execute("SELECT COUNT(*) FROM users WHERE role='user'").fetchone()[0]
    active_subs = conn.execute("SELECT COUNT(*) FROM subscriptions WHERE status='active'").fetchone()[0]
    expired_subs = conn.execute("SELECT COUNT(*) FROM subscriptions WHERE status='expired'").fetchone()[0]
    canceled_subs = conn.execute("SELECT COUNT(*) FROM subscriptions WHERE status IN ('canceled', 'canceling')").fetchone()[0]
    total_cancel_requests = conn.execute("SELECT COUNT(*) FROM cancellation_requests").fetchone()[0]
    pending_cancellations = conn.execute("SELECT COUNT(*) FROM cancellation_requests WHERE status='pending'").fetchone()[0]
    approved_cancellations = conn.execute("SELECT COUNT(*) FROM cancellation_requests WHERE status='approved'").fetchone()[0]
    rejected_cancellations = conn.execute("SELECT COUNT(*) FROM cancellation_requests WHERE status='rejected'").fetchone()[0]
    revenue = conn.execute("SELECT COALESCE(SUM(amount), 0) FROM payments WHERE status='paid'").fetchone()[0]
    plan_stats = conn.execute(
        """
        SELECT p.name, p.price, p.billing_cycle, p.status,
               COUNT(CASE WHEN s.status='active' THEN 1 END) as active_count,
               COUNT(CASE WHEN s.status='expired' THEN 1 END) as expired_count,
               COUNT(CASE WHEN s.status IN ('canceled','canceling') THEN 1 END) as canceled_count,
               COUNT(s.id) as total_subs
        FROM plans p LEFT JOIN subscriptions s ON p.id = s.plan_id
        GROUP BY p.id ORDER BY active_count DESC
        """
    ).fetchall()
    recent_users = conn.execute("SELECT name, email, created_at FROM users WHERE role='user' ORDER BY id DESC LIMIT 5").fetchall()
    recent_payments = conn.execute(
        """
        SELECT pay.*, u.name as user_name FROM payments pay JOIN users u ON pay.user_id=u.id ORDER BY pay.id DESC LIMIT 8
        """
    ).fetchall()
    conn.close()
    return render_template(
        "admin_reports.html",
        total_users=total_users,
        plan_stats=plan_stats,
        active_subs=active_subs,
        expired_subs=expired_subs,
        canceled_subs=canceled_subs,
        total_cancel_requests=total_cancel_requests,
        pending_cancellations=pending_cancellations,
        approved_cancellations=approved_cancellations,
        rejected_cancellations=rejected_cancellations,
        revenue=revenue,
        recent_users=recent_users,
        recent_payments=recent_payments,
    )


if __name__ == "__main__":
    app.run(debug=True)
