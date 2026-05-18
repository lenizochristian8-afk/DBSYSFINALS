import os
import hmac
import sqlite3
import secrets
import smtplib
import ssl
from email.message import EmailMessage
from datetime import datetime, timedelta
from functools import wraps

from dotenv import load_dotenv
from flask import Flask, request, render_template, redirect, session, flash, url_for, abort, make_response, jsonify
from markupsafe import Markup, escape
from werkzeug.security import generate_password_hash, check_password_hash

try:
    import stripe
except Exception:  # lets the app run even before requirements are installed
    stripe = None

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-secret-change-me")
DB_PATH = os.getenv("DATABASE_PATH", "database.db")
if stripe:
    stripe.api_key = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")

# -------------------------
# Database helpers
# -------------------------
def get_db():
    conn = sqlite3.connect(os.getenv("DATABASE_PATH", DB_PATH), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=10000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def table_columns(conn, table):
    return [r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]


def ensure_schema():
    conn = get_db()
    try:
        cols = table_columns(conn, "users") if conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'").fetchone() else []
        if cols:
            if "university" not in cols:
                conn.execute("ALTER TABLE users ADD COLUMN university TEXT DEFAULT ''")
            if "email_verified" not in cols:
                conn.execute("ALTER TABLE users ADD COLUMN email_verified INTEGER DEFAULT 1")
        cols = table_columns(conn, "plans") if conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='plans'").fetchone() else []
        if cols and "trial_days" not in cols:
            conn.execute("ALTER TABLE plans ADD COLUMN trial_days INTEGER DEFAULT 0")
        cols = table_columns(conn, "lesson_progress") if conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='lesson_progress'").fetchone() else []
        if cols and "progress_percent" not in cols:
            conn.execute("ALTER TABLE lesson_progress ADD COLUMN progress_percent INTEGER DEFAULT 0")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS email_otps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                university TEXT DEFAULT '',
                otp_hash TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                attempts INTEGER DEFAULT 0,
                created_at TEXT DEFAULT (datetime('now'))
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                link TEXT DEFAULT '',
                is_read INTEGER DEFAULT 0,
                created_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        # Ensure Free Trial exists.
        if conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='plans'").fetchone():
            free = conn.execute("SELECT id FROM plans WHERE lower(name)='free trial'").fetchone()
            if not free:
                conn.execute("""
                    INSERT INTO plans (name, description, price, billing_cycle, stripe_price_id, status, trial_days)
                    VALUES (?, ?, 0, 'Free Trial', '', 'active', 7)
                """, ("Free Trial", "Try Substra Learn free for 7 days. Includes starter course access."))
        conn.commit()
    finally:
        conn.close()


ensure_schema()


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def today_date():
    return datetime.now().strftime("%Y-%m-%d")


def log_admin_action(action, target_type=None, target_id=None, details=None, conn=None):
    own = conn is None
    conn = conn or get_db()
    try:
        conn.execute("""
            INSERT INTO admin_audit_logs (admin_id, action, target_type, target_id, details, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (session.get("user_id"), action, target_type, target_id, details, now_str()))
        if own:
            conn.commit()
    except Exception as e:
        print("Audit log error:", e)
    finally:
        if own:
            conn.close()


def notify_user(conn, user_id, title, message, link=""):
    conn.execute("""
        INSERT INTO notifications (user_id, title, message, link, is_read, created_at)
        VALUES (?, ?, ?, ?, 0, ?)
    """, (user_id, title, message, link, now_str()))


def notify_admins(conn, title, message, link=""):
    admins = conn.execute("SELECT id FROM users WHERE role='admin' AND status='active'").fetchall()
    for admin in admins:
        notify_user(conn, admin["id"], title, message, link)


# -------------------------
# CSRF helpers
# -------------------------
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
    if request.method != "POST" or request.endpoint == "stripe_webhook":
        return
    sent = request.form.get("csrf_token", "")
    expected = session.get("_csrf_token", "")
    if not expected or not hmac.compare_digest(sent, expected):
        abort(400, "Invalid CSRF token")


# -------------------------
# Auth decorators + badges
# -------------------------
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
def refresh_badges():
    if "user_id" not in session:
        return
    try:
        conn = get_db()
        session["notification_count"] = conn.execute(
            "SELECT COUNT(*) FROM notifications WHERE user_id=? AND is_read=0", (session["user_id"],)
        ).fetchone()[0]
        if session.get("role") == "admin":
            session["pending_count"] = conn.execute("SELECT COUNT(*) FROM cancellation_requests WHERE status='pending'").fetchone()[0]
            session["failed_payment_count"] = conn.execute("SELECT COUNT(*) FROM payments WHERE status='failed'").fetchone()[0]
        conn.close()
    except Exception:
        pass


# -------------------------
# Subscription/course helpers
# -------------------------
def auto_expire():
    conn = get_db()
    conn.execute("""
        UPDATE subscriptions
        SET status='expired'
        WHERE end_date < date('now') AND status='active'
    """)
    conn.execute("""
        UPDATE subscriptions
        SET status='canceled'
        WHERE end_date < date('now') AND status='canceling'
    """)
    conn.commit()
    conn.close()


def get_current_subscription(conn, user_id):
    return conn.execute("""
        SELECT s.*, p.name as plan_name, p.price, p.billing_cycle, p.trial_days, CASE WHEN p.trial_days > 0 THEN 299 ELSE p.price END as access_price
        FROM subscriptions s
        JOIN plans p ON s.plan_id = p.id
        WHERE s.user_id = ? AND s.status IN ('active', 'canceling') AND s.end_date >= date('now')
        ORDER BY s.id DESC LIMIT 1
    """, (user_id,)).fetchone()


def get_active_subscription(conn, user_id):
    return get_current_subscription(conn, user_id)


def user_can_access_course(conn, user_id, course_id):
    active_sub = get_current_subscription(conn, user_id)
    if not active_sub:
        return False, None, None
    course = conn.execute("""
        SELECT c.*, p.name as plan_name, p.price as plan_price
        FROM courses c JOIN plans p ON c.plan_id = p.id
        WHERE c.id = ? AND c.status='published'
    """, (course_id,)).fetchone()
    if not course:
        return False, active_sub, None
    return course["plan_price"] <= active_sub["access_price"], active_sub, course


def calculate_end_date(start_dt, billing_cycle, trial_days=0):
    if trial_days and int(trial_days) > 0:
        return start_dt + timedelta(days=int(trial_days))
    cycle = (billing_cycle or "monthly").lower()
    if cycle == "yearly":
        try:
            return start_dt.replace(year=start_dt.year + 1)
        except ValueError:
            return start_dt + timedelta(days=365)
    if cycle == "quarterly":
        return start_dt + timedelta(days=90)
    return start_dt + timedelta(days=30)


# -------------------------
# Email OTP helpers
# -------------------------
def password_errors(password):
    errors = []
    if len(password or "") < 8:
        errors.append("Password must be at least 8 characters long.")
    return errors


def send_otp_email(to_email, otp):
    """Send a registration OTP to the user's email using SMTP.

    Local testing:
      EMAIL_DEV_MODE=true prints the OTP in the terminal.

    Production/deployment with Resend:
      EMAIL_DEV_MODE=false
      SMTP_HOST=smtp.resend.com
      SMTP_PORT=587
      SMTP_USE_TLS=true
      SMTP_USE_SSL=false
      SMTP_USER=resend
      SMTP_PASSWORD=<your Resend API key>
      MAIL_FROM=<verified sender, e.g. onboarding@resend.dev or no-reply@yourdomain.com>
    """
    dev_mode = os.getenv("EMAIL_DEV_MODE", "true").lower() == "true"
    smtp_host = os.getenv("SMTP_HOST", "").strip()
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER", "").strip()
    smtp_password = os.getenv("SMTP_PASSWORD", "")
    mail_from = os.getenv("MAIL_FROM", smtp_user or "no-reply@substra-learn.local").strip()
    mail_from_name = os.getenv("MAIL_FROM_NAME", "Substra Learn").strip()
    use_tls = os.getenv("SMTP_USE_TLS", "true").lower() == "true"
    use_ssl = os.getenv("SMTP_USE_SSL", "false").lower() == "true"

    if dev_mode:
        print(f"[DEV OTP] {to_email}: {otp}")
        return True

    if not smtp_host:
        raise RuntimeError("SMTP_HOST is required when EMAIL_DEV_MODE=false")

    msg = EmailMessage()
    msg["Subject"] = "Your Substra Learn verification code"
    msg["From"] = f"{mail_from_name} <{mail_from}>"
    msg["To"] = to_email
    msg.set_content(
        "Hello,\n\n"
        f"Your Substra Learn verification code is: {otp}\n\n"
        "This code expires in 10 minutes. If you did not create an account, you can ignore this email.\n\n"
        "Substra Learn"
    )

    context = ssl.create_default_context()
    if use_ssl:
        with smtplib.SMTP_SSL(smtp_host, smtp_port, context=context, timeout=20) as server:
            if smtp_user:
                server.login(smtp_user, smtp_password)
            server.send_message(msg)
    else:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=20) as server:
            server.ehlo()
            if use_tls:
                server.starttls(context=context)
                server.ehlo()
            if smtp_user:
                server.login(smtp_user, smtp_password)
            server.send_message(msg)
    return True


# -------------------------
# Public/auth routes
# -------------------------
@app.route("/")
def home():
    return redirect("/dashboard" if session.get("user_id") else "/login")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        university = request.form.get("university", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if password != confirm:
            flash("Passwords do not match.", "danger")
            return redirect("/register")
        errors = password_errors(password)
        if errors:
            flash(" ".join(errors), "danger")
            return redirect("/register")
        if not university:
            flash("Please enter your university.", "danger")
            return redirect("/register")

        conn = get_db()
        try:
            if conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone():
                flash("Email already exists. Please login.", "danger")
                return redirect("/register")
            otp = f"{secrets.randbelow(1000000):06d}"
            conn.execute("DELETE FROM email_otps WHERE email=?", (email,))
            conn.execute("""
                INSERT INTO email_otps (name, email, password_hash, university, otp_hash, expires_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (name, email, generate_password_hash(password), university, generate_password_hash(otp),
                  (datetime.now() + timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S")))
            conn.commit()
            try:
                send_otp_email(email, otp)
            except Exception as e:
                conn.execute("DELETE FROM email_otps WHERE email=?", (email,))
                conn.commit()
                flash(f"Could not send verification email. Please contact support. Error: {str(e)}", "danger")
                return redirect("/register")
            session["pending_email"] = email
            if os.getenv("EMAIL_DEV_MODE", "true").lower() == "true":
                flash(f"Development OTP: {otp}", "info")
            else:
                flash("We sent a verification code to your email.", "success")
            return redirect("/verify-email")
        finally:
            conn.close()
    return render_template("register.html")


@app.route("/verify-email", methods=["GET", "POST"])
def verify_email():
    email = session.get("pending_email") or request.args.get("email", "").strip().lower()
    if not email:
        flash("Please register first.", "warning")
        return redirect("/register")
    if request.method == "POST":
        otp = request.form.get("otp", "").strip()
        conn = get_db()
        row = conn.execute("SELECT * FROM email_otps WHERE email=? ORDER BY id DESC LIMIT 1", (email,)).fetchone()
        if not row:
            conn.close()
            flash("Verification code expired. Please register again.", "danger")
            return redirect("/register")
        if datetime.strptime(row["expires_at"], "%Y-%m-%d %H:%M:%S") < datetime.now():
            conn.execute("DELETE FROM email_otps WHERE email=?", (email,))
            conn.commit(); conn.close()
            flash("Verification code expired. Please register again.", "danger")
            return redirect("/register")
        if not check_password_hash(row["otp_hash"], otp):
            conn.execute("UPDATE email_otps SET attempts=attempts+1 WHERE id=?", (row["id"],))
            conn.commit(); conn.close()
            flash("Invalid verification code.", "danger")
            return redirect("/verify-email")
        try:
            conn.execute("""
                INSERT INTO users (name, email, password, role, status, university, email_verified)
                VALUES (?, ?, ?, 'user', 'active', ?, 1)
            """, (row["name"], row["email"], row["password_hash"], row["university"]))
            conn.execute("DELETE FROM email_otps WHERE email=?", (email,))
            conn.commit()
            session.pop("pending_email", None)
            flash("Email verified. Your account has been created. Please login.", "success")
            return redirect("/login")
        except sqlite3.IntegrityError:
            flash("Email already exists. Please login.", "warning")
            return redirect("/login")
        finally:
            conn.close()
    return render_template("verify_email.html", email=email)


@app.route("/resend-otp", methods=["POST"])
def resend_otp():
    email = session.get("pending_email")
    if not email:
        flash("Please register first.", "warning")
        return redirect("/register")
    conn = get_db()
    row = conn.execute("SELECT * FROM email_otps WHERE email=? ORDER BY id DESC LIMIT 1", (email,)).fetchone()
    if not row:
        conn.close(); flash("Please register again.", "warning"); return redirect("/register")
    otp = f"{secrets.randbelow(1000000):06d}"
    conn.execute("UPDATE email_otps SET otp_hash=?, expires_at=?, attempts=0 WHERE id=?", (
        generate_password_hash(otp), (datetime.now() + timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S"), row["id"]
    ))
    conn.commit(); conn.close()
    try:
        send_otp_email(email, otp)
    except Exception as e:
        flash(f"Could not resend verification email. Error: {str(e)}", "danger")
        return redirect("/verify-email")
    flash(f"Development OTP: {otp}" if os.getenv("EMAIL_DEV_MODE", "true").lower() == "true" else "A new code has been sent.", "info")
    return redirect("/verify-email")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        conn.close()
        if user and user["status"] != "active":
            flash("This account is disabled. Contact support.", "danger")
            return redirect("/login")
        if user and not user["email_verified"]:
            flash("Please verify your email before logging in.", "warning")
            return redirect("/login")
        if user and check_password_hash(user["password"], password):
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


# -------------------------
# Notifications
# -------------------------
@app.route("/notifications")
@login_required
def notifications():
    conn = get_db()
    notes = conn.execute("SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 100", (session["user_id"],)).fetchall()
    conn.execute("UPDATE notifications SET is_read=1 WHERE user_id=?", (session["user_id"],))
    conn.commit(); conn.close()
    session["notification_count"] = 0
    return render_template("notifications.html", notifications=notes)


# -------------------------
# User routes
# -------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    if session.get("role") == "admin":
        return redirect("/admin")
    auto_expire()
    conn = get_db()
    subscriptions = conn.execute("""
        SELECT s.id, p.name as plan_name, s.start_date, s.end_date, s.status, p.price, p.billing_cycle
        FROM subscriptions s JOIN plans p ON s.plan_id = p.id
        WHERE s.user_id = ? ORDER BY s.id DESC
    """, (session["user_id"],)).fetchall()
    active_sub = get_current_subscription(conn, session["user_id"])
    course_count = 0
    if active_sub:
        course_count = conn.execute("""
            SELECT COUNT(*) FROM courses c JOIN plans p ON c.plan_id = p.id
            WHERE p.price <= ? AND c.status='published'
        """, (active_sub["access_price"],)).fetchone()[0]
    pending_cancel = None
    if active_sub:
        pending_cancel = conn.execute("SELECT * FROM cancellation_requests WHERE subscription_id=? AND status='pending'", (active_sub["id"],)).fetchone()
    conn.close()
    return render_template("dashboard.html", subscriptions=subscriptions, active_sub=active_sub, course_count=course_count, pending_cancel=pending_cancel)


@app.route("/plans")
@login_required
def plans():
    conn = get_db()
    all_plans = conn.execute("SELECT * FROM plans WHERE status='active' ORDER BY price, trial_days DESC").fetchall()
    active_sub = get_current_subscription(conn, session["user_id"])
    conn.close()
    return render_template("plans.html", plans=all_plans, active_plan_id=active_sub["plan_id"] if active_sub else None)


@app.route("/subscribe/<int:plan_id>")
@login_required
def subscribe(plan_id):
    conn = get_db()
    plan = conn.execute("SELECT * FROM plans WHERE id=? AND status='active'", (plan_id,)).fetchone()
    user = conn.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    if not plan:
        conn.close(); flash("Plan not available", "danger"); return redirect("/plans")
    # Free trial / free plan: activate immediately, no Stripe needed.
    if float(plan["price"]) <= 0 or int(plan["trial_days"] or 0) > 0:
        existing_trial = conn.execute("""
            SELECT s.id FROM subscriptions s JOIN plans p ON s.plan_id=p.id
            WHERE s.user_id=? AND p.trial_days > 0
        """, (session["user_id"],)).fetchone()
        if existing_trial:
            conn.close(); flash("You have already used the free trial.", "warning"); return redirect("/plans")
        now = datetime.now(); end = calculate_end_date(now, plan["billing_cycle"], plan["trial_days"])
        conn.execute("UPDATE subscriptions SET status='expired' WHERE user_id=? AND status IN ('active','canceling')", (session["user_id"],))
        conn.execute("""
            INSERT INTO subscriptions (user_id, plan_id, start_date, end_date, status)
            VALUES (?, ?, ?, ?, 'active')
        """, (session["user_id"], plan_id, now.strftime("%Y-%m-%d"), end.strftime("%Y-%m-%d")))
        conn.commit(); conn.close()
        flash("Your 7-day free trial is now active.", "success")
        return redirect("/dashboard")
    conn.close()
    if not plan["stripe_price_id"]:
        flash("This plan is not connected to Stripe yet.", "danger")
        return redirect("/plans")
    if not stripe or not os.getenv("STRIPE_SECRET_KEY"):
        flash("Stripe secret key is not configured.", "danger")
        return redirect("/plans")
    try:
        checkout_session = stripe.checkout.Session.create(
            mode="subscription",
            customer_email=user["email"],
            success_url=url_for("checkout_success", _external=True) + "?session_id={CHECKOUT_SESSION_ID}",
            cancel_url=url_for("checkout_cancel", _external=True),
            line_items=[{"price": plan["stripe_price_id"], "quantity": 1}],
            metadata={"user_id": str(user["id"]), "plan_id": str(plan["id"])}
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
        flash("Missing checkout session.", "danger"); return redirect("/plans")
    try:
        checkout_session = stripe.checkout.Session.retrieve(session_id)
    except Exception as e:
        flash(f"Unable to verify payment: {str(e)}", "danger"); return redirect("/plans")
    if checkout_session.payment_status != "paid":
        flash("Payment not completed.", "warning"); return redirect("/plans")
    metadata = checkout_session.metadata or {}
    user_id, plan_id = int(metadata["user_id"]), int(metadata["plan_id"])
    conn = get_db()
    existing = conn.execute("SELECT * FROM subscriptions WHERE checkout_session_id=?", (checkout_session.id,)).fetchone()
    payment_exists = conn.execute("SELECT * FROM payments WHERE stripe_checkout_session_id=?", (checkout_session.id,)).fetchone()
    plan = conn.execute("SELECT * FROM plans WHERE id=?", (plan_id,)).fetchone()
    if not existing:
        now = datetime.now(); end = calculate_end_date(now, plan["billing_cycle"], plan["trial_days"])
        conn.execute("UPDATE subscriptions SET status='expired' WHERE user_id=? AND status IN ('active','canceling')", (user_id,))
        cur = conn.execute("""
            INSERT INTO subscriptions (user_id, plan_id, start_date, end_date, status, stripe_customer_id, stripe_subscription_id, checkout_session_id)
            VALUES (?, ?, ?, ?, 'active', ?, ?, ?)
        """, (user_id, plan_id, now.strftime("%Y-%m-%d"), end.strftime("%Y-%m-%d"), checkout_session.customer or "", checkout_session.subscription or "", checkout_session.id))
        subscription_id = cur.lastrowid
    else:
        subscription_id = existing["id"]
    if not payment_exists:
        conn.execute("""
            INSERT INTO payments (user_id, subscription_id, plan_id, amount, currency, status, source, stripe_checkout_session_id, paid_at)
            VALUES (?, ?, ?, ?, 'PHP', 'paid', 'checkout_success', ?, ?)
        """, (user_id, subscription_id, plan_id, plan["price"], checkout_session.id, now_str()))
    conn.commit(); conn.close()
    flash("Payment successful. Your subscription is now active.", "success")
    return redirect("/dashboard")


@app.route("/checkout/cancel")
@login_required
def checkout_cancel():
    flash("Checkout canceled.", "warning")
    return redirect("/plans")


def create_subscription_from_checkout(checkout_session):
    user_id = int(checkout_session["metadata"]["user_id"]); plan_id = int(checkout_session["metadata"]["plan_id"])
    conn = get_db()
    existing = conn.execute("SELECT * FROM subscriptions WHERE checkout_session_id=?", (checkout_session["id"],)).fetchone()
    if existing:
        conn.close(); return existing["id"]
    plan = conn.execute("SELECT * FROM plans WHERE id=?", (plan_id,)).fetchone()
    now = datetime.now(); end = calculate_end_date(now, plan["billing_cycle"], plan["trial_days"])
    conn.execute("UPDATE subscriptions SET status='expired' WHERE user_id=? AND status IN ('active','canceling')", (user_id,))
    cur = conn.execute("""
        INSERT INTO subscriptions (user_id, plan_id, start_date, end_date, status, stripe_customer_id, stripe_subscription_id, checkout_session_id)
        VALUES (?, ?, ?, ?, 'active', ?, ?, ?)
    """, (user_id, plan_id, now.strftime("%Y-%m-%d"), end.strftime("%Y-%m-%d"), checkout_session.get("customer", ""), checkout_session.get("subscription", ""), checkout_session["id"]))
    sub_id = cur.lastrowid
    conn.execute("""
        INSERT INTO payments (user_id, subscription_id, plan_id, stripe_invoice_id, stripe_payment_intent_id, amount, currency, status, source, stripe_checkout_session_id, paid_at)
        VALUES (?, ?, ?, ?, ?, ?, 'PHP', 'paid', 'webhook', ?, ?)
    """, (user_id, sub_id, plan_id, checkout_session.get("invoice", ""), checkout_session.get("payment_intent", ""), float(plan["price"]), checkout_session["id"], now_str()))
    conn.commit(); conn.close(); return sub_id


@app.route("/stripe/webhook", methods=["POST"])
def stripe_webhook():
    payload = request.data; sig_header = request.headers.get("Stripe-Signature")
    if STRIPE_WEBHOOK_SECRET and stripe:
        try:
            event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
        except Exception:
            return "Invalid webhook", 400
    else:
        event = request.get_json(force=True, silent=True) or {}
    event_type = event.get("type"); obj = event.get("data", {}).get("object", {})
    if event_type == "checkout.session.completed" and obj.get("mode") == "subscription":
        create_subscription_from_checkout(obj)
    elif event_type == "invoice.payment_succeeded":
        record_invoice_payment(obj, "paid")
    elif event_type == "invoice.payment_failed":
        record_invoice_payment(obj, "failed")
    elif event_type == "customer.subscription.deleted":
        stripe_sub_id = obj.get("id")
        conn = get_db(); conn.execute("UPDATE subscriptions SET status='canceled' WHERE stripe_subscription_id=?", (stripe_sub_id,)); conn.commit(); conn.close()
    return "ok", 200


def record_invoice_payment(invoice, status):
    conn = get_db()
    sub = conn.execute("SELECT * FROM subscriptions WHERE stripe_subscription_id=?", (invoice.get("subscription", ""),)).fetchone()
    if sub:
        amount = (invoice.get("amount_paid") or invoice.get("amount_due") or 0) / 100
        paid_at = datetime.fromtimestamp(invoice.get("created", datetime.now().timestamp())).strftime("%Y-%m-%d %H:%M:%S")
        conn.execute("""
            INSERT INTO payments (user_id, subscription_id, plan_id, stripe_invoice_id, stripe_payment_intent_id, amount, currency, status, source, paid_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'webhook', ?)
        """, (sub["user_id"], sub["id"], sub["plan_id"], invoice.get("id", ""), invoice.get("payment_intent", ""), amount, (invoice.get("currency") or "php").upper(), status, paid_at))
        if status == "failed":
            conn.execute("UPDATE subscriptions SET status='past_due' WHERE id=?", (sub["id"],))
        conn.commit()
    conn.close()


def normalize_video_url(url):
    if not url: return ""
    url = url.strip()
    if "youtube.com/embed/" in url: return url
    if "youtube.com/watch?v=" in url:
        return "https://www.youtube.com/embed/" + url.split("watch?v=")[1].split("&")[0]
    if "youtu.be/" in url:
        return "https://www.youtube.com/embed/" + url.split("youtu.be/")[1].split("?")[0]
    if "youtube.com/shorts/" in url:
        return "https://www.youtube.com/embed/" + url.split("youtube.com/shorts/")[1].split("?")[0]
    return url


@app.route("/my-courses")
@login_required
def my_courses():
    conn = get_db(); active_sub = get_current_subscription(conn, session["user_id"]); courses = []
    if active_sub:
        courses = conn.execute("""
            SELECT c.*, p.name as plan_name,
                   COUNT(DISTINCT l.id) as total_lessons,
                   COUNT(DISTINCT CASE WHEN COALESCE(lp.progress_percent, 0) >= 100 THEN l.id END) as completed_lessons,
                   COALESCE(ROUND(AVG(COALESCE(lp.progress_percent, 0))), 0) as avg_lesson_percent
            FROM courses c JOIN plans p ON c.plan_id = p.id
            LEFT JOIN lessons l ON l.course_id = c.id AND l.status='published'
            LEFT JOIN lesson_progress lp ON lp.lesson_id = l.id AND lp.user_id = ?
            WHERE p.price <= ? AND c.status='published'
            GROUP BY c.id ORDER BY p.price, c.title
        """, (session["user_id"], active_sub["access_price"])).fetchall()
    conn.close(); return render_template("my_courses.html", courses=courses, active_sub=active_sub)


@app.route("/course/<int:course_id>")
@login_required
def course_detail(course_id):
    conn = get_db(); can_access, active_sub, course = user_can_access_course(conn, session["user_id"], course_id)
    if not course:
        conn.close(); flash("Course not found", "danger"); return redirect("/my-courses")
    if not can_access:
        conn.close(); flash("Subscribe to the required plan to access this course.", "warning"); return redirect("/plans")
    lessons = conn.execute("""
        SELECT l.*, COALESCE(lp.progress_percent, 0) as lesson_percent,
               CASE WHEN COALESCE(lp.progress_percent, 0) >= 100 THEN 1 ELSE 0 END as is_completed
        FROM lessons l LEFT JOIN lesson_progress lp ON lp.lesson_id = l.id AND lp.user_id = ?
        WHERE l.course_id = ? AND l.status='published'
        ORDER BY l.position, l.id
    """, (session["user_id"], course_id)).fetchall()
    total_lessons = len(lessons)
    completed_lessons = sum(1 for lesson in lessons if lesson["is_completed"])
    progress_percent = round(sum(int(lesson["lesson_percent"] or 0) for lesson in lessons) / total_lessons) if total_lessons else 0
    conn.close()
    return render_template("course_detail.html", course=course, lessons=lessons, active_sub=active_sub, completed_lessons=completed_lessons, total_lessons=total_lessons, progress_percent=progress_percent)


@app.route("/lesson/<int:lesson_id>")
@login_required
def lesson_detail(lesson_id):
    conn = get_db()
    lesson = conn.execute("""
        SELECT l.*, c.id as course_id, c.title as course_title, p.name as plan_name, p.price as plan_price
        FROM lessons l JOIN courses c ON l.course_id = c.id JOIN plans p ON c.plan_id = p.id
        WHERE l.id = ? AND l.status='published' AND c.status='published'
    """, (lesson_id,)).fetchone()
    if not lesson:
        conn.close(); flash("Lesson not found", "danger"); return redirect("/my-courses")
    can_access, active_sub, course = user_can_access_course(conn, session["user_id"], lesson["course_id"])
    if not can_access:
        conn.close(); flash("Subscribe to the required plan to access this lesson.", "warning"); return redirect("/plans")
    progress = conn.execute("SELECT * FROM lesson_progress WHERE user_id=? AND lesson_id=?", (session["user_id"], lesson_id)).fetchone()
    previous_lesson = conn.execute("""SELECT id, title FROM lessons WHERE course_id=? AND status='published' AND (position < ? OR (position = ? AND id < ?)) ORDER BY position DESC, id DESC LIMIT 1""", (lesson["course_id"], lesson["position"], lesson["position"], lesson_id)).fetchone()
    next_lesson = conn.execute("""SELECT id, title FROM lessons WHERE course_id=? AND status='published' AND (position > ? OR (position = ? AND id > ?)) ORDER BY position ASC, id ASC LIMIT 1""", (lesson["course_id"], lesson["position"], lesson["position"], lesson_id)).fetchone()
    conn.close(); return render_template("lesson_detail.html", lesson=lesson, course=course, progress=progress, previous_lesson=previous_lesson, next_lesson=next_lesson)


def save_lesson_progress(conn, user_id, lesson_id, percent):
    """Save the highest scroll/read percentage reached for a lesson."""
    percent = max(0, min(100, int(percent or 0)))
    existing = conn.execute(
        "SELECT progress_percent FROM lesson_progress WHERE user_id=? AND lesson_id=?",
        (user_id, lesson_id),
    ).fetchone()
    current = int(existing["progress_percent"] or 0) if existing else 0
    saved_percent = max(current, percent)
    completed_at = now_str() if saved_percent >= 100 else None
    if existing:
        if completed_at:
            conn.execute(
                "UPDATE lesson_progress SET progress_percent=?, completed_at=? WHERE user_id=? AND lesson_id=?",
                (saved_percent, completed_at, user_id, lesson_id),
            )
        else:
            conn.execute(
                "UPDATE lesson_progress SET progress_percent=? WHERE user_id=? AND lesson_id=?",
                (saved_percent, user_id, lesson_id),
            )
    else:
        conn.execute(
            "INSERT INTO lesson_progress (user_id, lesson_id, completed_at, progress_percent) VALUES (?, ?, ?, ?)",
            (user_id, lesson_id, completed_at, saved_percent),
        )
    return saved_percent


@app.route("/lesson/<int:lesson_id>/progress", methods=["POST"])
@login_required
def update_lesson_progress(lesson_id):
    try:
        percent = int(float(request.form.get("progress_percent", 0) or 0))
    except Exception:
        percent = 0
    conn = get_db()
    lesson = conn.execute("SELECT * FROM lessons WHERE id=? AND status='published'", (lesson_id,)).fetchone()
    if not lesson:
        conn.close(); return jsonify({"ok": False, "error": "Lesson not found"}), 404
    can_access, active_sub, course = user_can_access_course(conn, session["user_id"], lesson["course_id"])
    if not can_access:
        conn.close(); return jsonify({"ok": False, "error": "Access denied"}), 403
    saved_percent = save_lesson_progress(conn, session["user_id"], lesson_id, percent)
    conn.commit(); conn.close()
    return jsonify({"ok": True, "progress_percent": saved_percent, "completed": saved_percent >= 100})


@app.route("/lesson/<int:lesson_id>/complete", methods=["POST"])
@login_required
def complete_lesson(lesson_id):
    try:
        percent = int(float(request.form.get("progress_percent", 100) or 100))
    except Exception:
        percent = 100
    conn = get_db(); lesson = conn.execute("SELECT * FROM lessons WHERE id=? AND status='published'", (lesson_id,)).fetchone()
    if not lesson:
        conn.close(); flash("Lesson not found", "danger"); return redirect("/my-courses")
    can_access, active_sub, course = user_can_access_course(conn, session["user_id"], lesson["course_id"])
    if not can_access:
        conn.close(); flash("You do not have access to this lesson.", "danger"); return redirect("/plans")
    saved_percent = save_lesson_progress(conn, session["user_id"], lesson_id, percent)
    conn.commit(); conn.close()
    flash("Lesson progress saved", "success")
    return redirect(request.form.get("next") or url_for("lesson_detail", lesson_id=lesson_id))


@app.route("/request-cancellation/<int:sub_id>", methods=["POST"])
@login_required
def request_cancellation(sub_id):
    conn = get_db()
    sub = conn.execute("SELECT * FROM subscriptions WHERE id=? AND user_id=? AND status IN ('active','canceling')", (sub_id, session["user_id"])).fetchone()
    if not sub:
        conn.close(); flash("Invalid subscription", "danger"); return redirect("/dashboard")
    existing = conn.execute("SELECT * FROM cancellation_requests WHERE subscription_id=? AND status='pending'", (sub_id,)).fetchone()
    if existing:
        conn.close(); flash("You already have a pending cancellation request", "warning"); return redirect("/cancellation-status")
    cur = conn.execute("""
        INSERT INTO cancellation_requests (subscription_id, user_id, reason, cancel_mode, status, created_at)
        VALUES (?, ?, ?, 'period_end', 'pending', ?)
    """, (sub_id, session["user_id"], request.form.get("reason", ""), now_str()))
    notify_admins(conn, "New cancellation request", f"{session.get('user_name')} requested subscription cancellation.", "/admin/cancellations")
    conn.commit(); conn.close()
    flash("Cancellation request submitted. Your access remains active while the request is reviewed.", "success")
    return redirect("/cancellation-status")


@app.route("/cancellation-status")
@login_required
def cancellation_status():
    conn = get_db()
    requests = conn.execute("""
        SELECT cr.*, p.name as plan_name, s.start_date, s.end_date
        FROM cancellation_requests cr JOIN subscriptions s ON cr.subscription_id = s.id JOIN plans p ON s.plan_id = p.id
        WHERE cr.user_id = ? ORDER BY cr.created_at DESC
    """, (session["user_id"],)).fetchall()
    conn.close(); return render_template("cancellation_status.html", requests=requests)


# -------------------------
# Admin routes
# -------------------------
@app.route("/admin")
@admin_required
def admin():
    auto_expire(); conn = get_db()
    total_users = conn.execute("SELECT COUNT(*) FROM users WHERE role='user'").fetchone()[0]
    active_subs = conn.execute("SELECT COUNT(*) FROM subscriptions WHERE status IN ('active','canceling') AND end_date >= date('now')").fetchone()[0]
    pending_cancellations = conn.execute("SELECT COUNT(*) FROM cancellation_requests WHERE status='pending'").fetchone()[0]
    total_courses = conn.execute("SELECT COUNT(*) FROM courses").fetchone()[0]
    failed_payments = conn.execute("SELECT COUNT(*) FROM payments WHERE status='failed'").fetchone()[0]
    revenue = conn.execute("SELECT COALESCE(SUM(amount), 0) FROM payments WHERE status='paid' AND paid_at >= date('now', 'start of month')").fetchone()[0]
    recent_subs = conn.execute("""SELECT s.id, u.name as user_name, p.name as plan_name, s.status, s.start_date, s.end_date FROM subscriptions s JOIN users u ON s.user_id = u.id JOIN plans p ON s.plan_id = p.id ORDER BY s.id DESC LIMIT 10""").fetchall()
    plans = conn.execute("SELECT * FROM plans ORDER BY price, trial_days DESC").fetchall()
    recent_logs = conn.execute("""SELECT l.*, u.name as admin_name FROM admin_audit_logs l JOIN users u ON l.admin_id = u.id ORDER BY l.id DESC LIMIT 8""").fetchall()
    conn.close()
    return render_template("admin.html", total_users=total_users, active_subs=active_subs, pending_cancellations=pending_cancellations, total_courses=total_courses, failed_payments=failed_payments, revenue=revenue, recent_subs=recent_subs, plans=plans, recent_logs=recent_logs)


@app.route("/admin/create_plan", methods=["POST"])
@admin_required
def create_plan():
    data = request.form; conn = get_db()
    trial_days = int(data.get("trial_days", 0) or 0)
    cur = conn.execute("""INSERT INTO plans (name, description, price, billing_cycle, stripe_price_id, status, trial_days) VALUES (?, ?, ?, ?, ?, 'active', ?)""", (data["name"].strip(), data.get("description", ""), data["price"], data["billing_cycle"], data.get("stripe_price_id", "").strip(), trial_days))
    log_admin_action("created plan", "plan", cur.lastrowid, data["name"], conn=conn)
    conn.commit(); conn.close(); flash("Plan created successfully", "success"); return redirect("/admin")


@app.route("/admin/edit_plan/<int:plan_id>", methods=["GET", "POST"])
@admin_required
def edit_plan(plan_id):
    conn = get_db()
    if request.method == "POST":
        data = request.form
        conn.execute("UPDATE plans SET name=?, description=?, price=?, billing_cycle=?, stripe_price_id=?, trial_days=? WHERE id=?", (data["name"].strip(), data.get("description", ""), data["price"], data["billing_cycle"], data.get("stripe_price_id", "").strip(), int(data.get("trial_days", 0) or 0), plan_id))
        log_admin_action("updated plan", "plan", plan_id, data["name"], conn=conn)
        conn.commit(); conn.close(); flash("Plan updated successfully", "success"); return redirect("/admin")
    plan = conn.execute("SELECT * FROM plans WHERE id=?", (plan_id,)).fetchone(); conn.close()
    if not plan: flash("Plan not found", "danger"); return redirect("/admin")
    return render_template("admin_edit_plan.html", plan=plan)


@app.route("/admin/toggle_plan/<int:plan_id>", methods=["POST"])
@admin_required
def toggle_plan(plan_id):
    conn = get_db(); plan = conn.execute("SELECT status FROM plans WHERE id=?", (plan_id,)).fetchone()
    if plan:
        new_status = "inactive" if plan["status"] == "active" else "active"
        conn.execute("UPDATE plans SET status=? WHERE id=?", (new_status, plan_id)); log_admin_action("toggled plan", "plan", plan_id, new_status, conn=conn); conn.commit(); flash(f"Plan {'activated' if new_status == 'active' else 'deactivated'}", "success")
    conn.close(); return redirect("/admin")


@app.route("/admin/delete_plan/<int:plan_id>", methods=["POST"])
@admin_required
def delete_plan(plan_id):
    conn = get_db(); in_use = conn.execute("SELECT COUNT(*) FROM subscriptions WHERE plan_id=?", (plan_id,)).fetchone()[0]
    if in_use:
        flash("Cannot delete a plan with existing subscriptions. Deactivate it instead.", "warning")
    else:
        conn.execute("DELETE FROM plans WHERE id=?", (plan_id,)); log_admin_action("deleted plan", "plan", plan_id, conn=conn); conn.commit(); flash("Plan deleted", "success")
    conn.close(); return redirect("/admin")


@app.route("/admin/users")
@admin_required
def admin_users():
    q = request.args.get("q", "").strip(); status = request.args.get("status", "")
    conn = get_db(); sql = """SELECT u.*, (SELECT COUNT(*) FROM subscriptions WHERE user_id=u.id AND status IN ('active','canceling')) as active_subs, (SELECT p.name FROM subscriptions s JOIN plans p ON s.plan_id=p.id WHERE s.user_id=u.id AND s.status IN ('active','canceling') ORDER BY s.id DESC LIMIT 1) as current_plan FROM users u WHERE u.role='user'"""; params=[]
    if q: sql += " AND (u.name LIKE ? OR u.email LIKE ? OR u.university LIKE ?)"; params.extend([f"%{q}%", f"%{q}%", f"%{q}%"])
    if status: sql += " AND u.status=?"; params.append(status)
    sql += " ORDER BY u.id DESC"; users = conn.execute(sql, params).fetchall(); conn.close()
    return render_template("admin_users.html", users=users, q=q, status=status)


@app.route("/admin/user/<int:user_id>")
@admin_required
def admin_user_detail(user_id):
    conn = get_db(); user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not user: conn.close(); flash("User not found", "danger"); return redirect("/admin/users")
    subs = conn.execute("""SELECT s.*, p.name as plan_name, p.price, p.billing_cycle FROM subscriptions s JOIN plans p ON s.plan_id=p.id WHERE s.user_id=? ORDER BY s.id DESC""", (user_id,)).fetchall()
    progress = conn.execute("""SELECT c.id, c.title, COUNT(DISTINCT l.id) total_lessons, COUNT(DISTINCT CASE WHEN COALESCE(lp.progress_percent,0)>=100 THEN l.id END) completed_lessons FROM courses c LEFT JOIN lessons l ON l.course_id=c.id LEFT JOIN lesson_progress lp ON lp.lesson_id=l.id AND lp.user_id=? GROUP BY c.id ORDER BY c.title""", (user_id,)).fetchall()
    payments = conn.execute("SELECT * FROM payments WHERE user_id=? ORDER BY id DESC", (user_id,)).fetchall()
    plans = conn.execute("SELECT * FROM plans WHERE status='active' ORDER BY price").fetchall(); conn.close()
    return render_template("admin_user_detail.html", user=user, subs=subs, progress=progress, payments=payments, plans=plans)


@app.route("/admin/user/<int:user_id>/toggle_status", methods=["POST"])
@admin_required
def admin_toggle_user_status(user_id):
    conn = get_db(); user = conn.execute("SELECT status FROM users WHERE id=? AND role='user'", (user_id,)).fetchone()
    if user:
        new_status = "disabled" if user["status"] == "active" else "active"; conn.execute("UPDATE users SET status=? WHERE id=?", (new_status, user_id)); log_admin_action("changed user status", "user", user_id, new_status, conn=conn); conn.commit(); flash("User status updated", "success")
    conn.close(); return redirect(url_for("admin_user_detail", user_id=user_id))


@app.route("/admin/user/<int:user_id>/assign_plan", methods=["POST"])
@admin_required
def admin_assign_plan(user_id):
    plan_id = request.form.get("plan_id"); days = int(request.form.get("days", 30)); conn = get_db(); plan = conn.execute("SELECT * FROM plans WHERE id=?", (plan_id,)).fetchone()
    if not plan: conn.close(); flash("Invalid plan", "danger"); return redirect(url_for("admin_user_detail", user_id=user_id))
    start = datetime.now(); end = start + timedelta(days=days)
    conn.execute("UPDATE subscriptions SET status='expired' WHERE user_id=? AND status IN ('active','canceling')", (user_id,))
    conn.execute("INSERT INTO subscriptions (user_id, plan_id, start_date, end_date, status) VALUES (?, ?, ?, ?, 'active')", (user_id, plan_id, start.strftime("%Y-%m-%d"), end.strftime("%Y-%m-%d")))
    log_admin_action("assigned manual plan", "user", user_id, f"plan {plan_id}, {days} days", conn=conn); conn.commit(); conn.close(); flash("Manual subscription assigned", "success"); return redirect(url_for("admin_user_detail", user_id=user_id))


@app.route("/admin/subscriptions")
@admin_required
def admin_subscriptions():
    q = request.args.get("q", "").strip(); status = request.args.get("status", ""); conn = get_db()
    sql = """SELECT s.*, u.name as user_name, u.email, p.name as plan_name, p.price, p.billing_cycle FROM subscriptions s JOIN users u ON s.user_id=u.id JOIN plans p ON s.plan_id=p.id WHERE 1=1"""; params=[]
    if q: sql += " AND (u.name LIKE ? OR u.email LIKE ? OR p.name LIKE ? OR s.stripe_subscription_id LIKE ?)"; params.extend([f"%{q}%", f"%{q}%", f"%{q}%", f"%{q}%"])
    if status: sql += " AND s.status=?"; params.append(status)
    sql += " ORDER BY s.id DESC"; subscriptions = conn.execute(sql, params).fetchall(); plans = conn.execute("SELECT * FROM plans WHERE status='active' ORDER BY price").fetchall(); conn.close()
    return render_template("admin_subscriptions.html", subscriptions=subscriptions, plans=plans, q=q, status=status)


@app.route("/admin/subscription/<int:sub_id>/cancel", methods=["POST"])
@admin_required
def admin_cancel_subscription(sub_id):
    conn = get_db(); sub = conn.execute("SELECT * FROM subscriptions WHERE id=?", (sub_id,)).fetchone()
    if not sub: conn.close(); flash("Subscription not found", "danger"); return redirect("/admin/subscriptions")
    conn.execute("UPDATE subscriptions SET status='canceling' WHERE id=?", (sub_id,)); log_admin_action("scheduled subscription cancellation", "subscription", sub_id, "period_end", conn=conn); notify_user(conn, sub["user_id"], "Subscription cancellation scheduled", "Your subscription will remain usable until its expiration date, then it will be canceled.", "/dashboard"); conn.commit(); conn.close()
    if sub["stripe_subscription_id"] and stripe and os.getenv("STRIPE_SECRET_KEY"):
        try: stripe.Subscription.modify(sub["stripe_subscription_id"], cancel_at_period_end=True)
        except Exception as e: flash(f"Local status updated, but Stripe sync failed: {str(e)}", "warning")
    flash("Subscription will remain usable until the expiration date.", "success"); return redirect("/admin/subscriptions")


@app.route("/admin/subscription/<int:sub_id>/change_plan", methods=["POST"])
@admin_required
def admin_change_subscription_plan(sub_id):
    plan_id = request.form.get("plan_id"); conn = get_db(); conn.execute("UPDATE subscriptions SET plan_id=? WHERE id=?", (plan_id, sub_id)); log_admin_action("changed subscription plan", "subscription", sub_id, f"plan {plan_id}", conn=conn); conn.commit(); conn.close(); flash("Subscription plan changed locally", "success"); return redirect("/admin/subscriptions")


@app.route("/admin/payments")
@admin_required
def admin_payments():
    q = request.args.get("q", "").strip(); status = request.args.get("status", ""); conn = get_db()
    sql = """SELECT pay.*, u.name as user_name, u.email, p.name as plan_name FROM payments pay JOIN users u ON pay.user_id=u.id LEFT JOIN plans p ON pay.plan_id=p.id WHERE 1=1"""; params=[]
    if q: sql += " AND (u.name LIKE ? OR u.email LIKE ? OR pay.stripe_invoice_id LIKE ? OR pay.stripe_checkout_session_id LIKE ?)"; params.extend([f"%{q}%", f"%{q}%", f"%{q}%", f"%{q}%"])
    if status: sql += " AND pay.status=?"; params.append(status)
    sql += " ORDER BY pay.id DESC"; payments = conn.execute(sql, params).fetchall(); conn.close(); return render_template("admin_payments.html", payments=payments, q=q, status=status)


@app.route("/admin/courses")
@admin_required
def admin_courses():
    conn = get_db(); courses = conn.execute("""SELECT c.*, p.name as plan_name, COUNT(DISTINCT l.id) as lesson_count FROM courses c JOIN plans p ON c.plan_id = p.id LEFT JOIN lessons l ON l.course_id=c.id GROUP BY c.id ORDER BY p.price, c.title""").fetchall(); plans = conn.execute("SELECT * FROM plans WHERE status='active' ORDER BY price").fetchall(); conn.close(); return render_template("admin_courses.html", courses=courses, plans=plans)


@app.route("/admin/create_course", methods=["POST"])
@admin_required
def create_course():
    data = request.form; conn = get_db(); cur = conn.execute("""INSERT INTO courses (title, description, plan_id, status, thumbnail_url, level, duration) VALUES (?, ?, ?, ?, ?, ?, ?)""", (data["title"].strip(), data.get("description", ""), data["plan_id"], data.get("status", "draft"), data.get("thumbnail_url", ""), data.get("level", ""), data.get("duration", "")))
    log_admin_action("created course", "course", cur.lastrowid, data["title"], conn=conn); conn.commit(); conn.close(); flash("Course added successfully", "success"); return redirect("/admin/courses")


@app.route("/admin/edit_course/<int:course_id>", methods=["POST"])
@admin_required
def edit_course(course_id):
    data = request.form; conn = get_db(); conn.execute("UPDATE courses SET title=?, description=?, plan_id=?, status=?, thumbnail_url=?, level=?, duration=? WHERE id=?", (data["title"].strip(), data.get("description", ""), data["plan_id"], data.get("status", "draft"), data.get("thumbnail_url", ""), data.get("level", ""), data.get("duration", ""), course_id)); log_admin_action("updated course", "course", course_id, data["title"], conn=conn); conn.commit(); conn.close(); flash("Course updated", "success"); return redirect("/admin/courses")


@app.route("/admin/delete_course/<int:course_id>", methods=["POST"])
@admin_required
def delete_course(course_id):
    conn = get_db(); conn.execute("DELETE FROM courses WHERE id=?", (course_id,)); log_admin_action("deleted course", "course", course_id, conn=conn); conn.commit(); conn.close(); flash("Course deleted", "success"); return redirect("/admin/courses")


@app.route("/admin/course/<int:course_id>/lessons")
@admin_required
def admin_course_lessons(course_id):
    conn = get_db(); course = conn.execute("SELECT c.*, p.name as plan_name FROM courses c JOIN plans p ON c.plan_id=p.id WHERE c.id=?", (course_id,)).fetchone()
    if not course: conn.close(); flash("Course not found", "danger"); return redirect("/admin/courses")
    lessons = conn.execute("SELECT * FROM lessons WHERE course_id=? ORDER BY position, id", (course_id,)).fetchall(); conn.close(); return render_template("admin_course_lessons.html", course=course, lessons=lessons)


@app.route("/admin/course/<int:course_id>/lessons/create", methods=["POST"])
@admin_required
def admin_create_lesson(course_id):
    title = request.form.get("title", "").strip(); content = request.form.get("content", "").strip(); video_url = normalize_video_url(request.form.get("video_url", "")); status = request.form.get("status", "published").strip(); position = int(request.form.get("position", 0) or 0); duration_minutes = int(request.form.get("duration_minutes", 0) or 0)
    if not title: flash("Lesson title is required.", "danger"); return redirect(url_for("admin_course_lessons", course_id=course_id))
    conn = get_db(); course = conn.execute("SELECT * FROM courses WHERE id=?", (course_id,)).fetchone()
    if not course: conn.close(); flash("Course not found.", "danger"); return redirect("/admin/courses")
    conn.execute("INSERT INTO lessons (course_id, title, content, video_url, position, status, duration_minutes) VALUES (?, ?, ?, ?, ?, ?, ?)", (course_id, title, content, video_url, position, status, duration_minutes)); log_admin_action("created lesson", "course", course_id, title, conn=conn); conn.commit(); conn.close(); flash("Lesson added successfully.", "success"); return redirect(url_for("admin_course_lessons", course_id=course_id))


@app.route("/admin/lesson/<int:lesson_id>/edit", methods=["POST"])
@admin_required
def admin_edit_lesson(lesson_id):
    title = request.form.get("title", "").strip(); content = request.form.get("content", "").strip(); video_url = normalize_video_url(request.form.get("video_url", "")); status = request.form.get("status", "published").strip(); position = int(request.form.get("position", 0) or 0); duration_minutes = int(request.form.get("duration_minutes", 0) or 0)
    conn = get_db(); lesson = conn.execute("SELECT * FROM lessons WHERE id=?", (lesson_id,)).fetchone()
    if not lesson: conn.close(); flash("Lesson not found.", "danger"); return redirect("/admin/courses")
    conn.execute("UPDATE lessons SET title=?, content=?, video_url=?, position=?, status=?, duration_minutes=? WHERE id=?", (title, content, video_url, position, status, duration_minutes, lesson_id)); log_admin_action("updated lesson", "lesson", lesson_id, title, conn=conn); conn.commit(); course_id = lesson["course_id"]; conn.close(); flash("Lesson updated successfully.", "success"); return redirect(url_for("admin_course_lessons", course_id=course_id))


@app.route("/admin/lesson/<int:lesson_id>/delete", methods=["POST"])
@admin_required
def admin_delete_lesson(lesson_id):
    conn = get_db(); lesson = conn.execute("SELECT * FROM lessons WHERE id=?", (lesson_id,)).fetchone()
    if not lesson: conn.close(); flash("Lesson not found", "danger"); return redirect("/admin/courses")
    course_id = lesson["course_id"]; conn.execute("DELETE FROM lesson_progress WHERE lesson_id=?", (lesson_id,)); conn.execute("DELETE FROM lessons WHERE id=?", (lesson_id,)); log_admin_action("deleted lesson", "lesson", lesson_id, conn=conn); conn.commit(); conn.close(); flash("Lesson deleted", "success"); return redirect(url_for("admin_course_lessons", course_id=course_id))


@app.route("/admin/cancellations")
@admin_required
def admin_cancellations():
    conn = get_db(); requests_ = conn.execute("""SELECT cr.*, u.name as user_name, u.email, p.name as plan_name, s.start_date, s.end_date FROM cancellation_requests cr JOIN users u ON cr.user_id = u.id JOIN subscriptions s ON cr.subscription_id = s.id JOIN plans p ON s.plan_id = p.id ORDER BY (cr.status = 'pending') DESC, cr.created_at DESC""").fetchall(); conn.close(); return render_template("admin_cancellations.html", requests=requests_)


@app.route("/admin/process_cancellation/<int:req_id>", methods=["POST"])
@admin_required
def process_cancellation(req_id):
    action = request.form.get("action"); conn = get_db(); cr = conn.execute("""SELECT cr.*, s.stripe_subscription_id, s.id as subscription_id, s.end_date FROM cancellation_requests cr JOIN subscriptions s ON cr.subscription_id = s.id WHERE cr.id=?""", (req_id,)).fetchone()
    if not cr: conn.close(); flash("Cancellation request not found.", "danger"); return redirect("/admin/cancellations")
    if cr["status"] != "pending": conn.close(); flash("This request has already been processed.", "warning"); return redirect("/admin/cancellations")
    if action == "approve":
        conn.execute("UPDATE cancellation_requests SET status='approved', processed_at=?, cancel_mode='period_end' WHERE id=?", (now_str(), req_id))
        conn.execute("UPDATE subscriptions SET status='canceling' WHERE id=?", (cr["subscription_id"],))
        notify_user(conn, cr["user_id"], "Cancellation approved", f"Your cancellation was approved. You can still use your subscription until {cr['end_date']}.", "/cancellation-status")
        log_admin_action("approved cancellation", "cancellation_request", req_id, "period_end", conn=conn); conn.commit(); conn.close()
        if cr["stripe_subscription_id"] and stripe and os.getenv("STRIPE_SECRET_KEY"):
            try: stripe.Subscription.modify(cr["stripe_subscription_id"], cancel_at_period_end=True)
            except Exception as e: flash(f"Cancellation approved locally, but Stripe sync failed: {str(e)}", "warning"); return redirect("/admin/cancellations")
        flash("Cancellation approved. Access remains usable until the subscription expiration date.", "success"); return redirect("/admin/cancellations")
    if action == "reject":
        conn.execute("UPDATE cancellation_requests SET status='rejected', processed_at=? WHERE id=?", (now_str(), req_id)); notify_user(conn, cr["user_id"], "Cancellation request rejected", "Your cancellation request was rejected. Your subscription remains active.", "/cancellation-status"); log_admin_action("rejected cancellation", "cancellation_request", req_id, "", conn=conn); conn.commit(); conn.close(); flash("Cancellation rejected.", "info"); return redirect("/admin/cancellations")
    conn.close(); flash("Invalid cancellation action.", "danger"); return redirect("/admin/cancellations")


@app.route("/admin/progress")
@admin_required
def admin_progress():
    conn = get_db(); rows = conn.execute("""
        SELECT u.id as user_id, u.name, u.email, c.id as course_id, c.title as course_title,
               l.id as lesson_id, l.title as lesson_title, l.position,
               COALESCE(lp.progress_percent, 0) as lesson_percent,
               (SELECT COALESCE(ROUND(AVG(COALESCE(lp2.progress_percent,0))),0)
                FROM lessons l2 LEFT JOIN lesson_progress lp2 ON lp2.lesson_id=l2.id AND lp2.user_id=u.id
                WHERE l2.course_id=c.id AND l2.status='published') as course_percent
        FROM users u
        JOIN subscriptions s ON s.user_id=u.id AND s.status IN ('active','canceling')
        JOIN plans p ON p.id=s.plan_id
        JOIN courses c ON c.status='published' JOIN plans cp ON cp.id=c.plan_id AND cp.price <= (CASE WHEN p.trial_days > 0 THEN 299 ELSE p.price END)
        JOIN lessons l ON l.course_id=c.id AND l.status='published'
        LEFT JOIN lesson_progress lp ON lp.lesson_id=l.id AND lp.user_id=u.id
        WHERE u.role='user'
        ORDER BY u.name, c.title, l.position, l.id
    """).fetchall(); conn.close(); return render_template("admin_progress.html", rows=rows)


@app.route("/admin/reports")
@admin_required
def admin_reports():
    data = build_report_data(); return render_template("admin_reports.html", **data)


def build_report_data():
    conn = get_db()
    data = {
        "total_users": conn.execute("SELECT COUNT(*) FROM users WHERE role='user'").fetchone()[0],
        "active_subs": conn.execute("SELECT COUNT(*) FROM subscriptions WHERE status IN ('active','canceling') AND end_date >= date('now')").fetchone()[0],
        "expired_subs": conn.execute("SELECT COUNT(*) FROM subscriptions WHERE status='expired'").fetchone()[0],
        "canceled_subs": conn.execute("SELECT COUNT(*) FROM subscriptions WHERE status IN ('canceled','canceling')").fetchone()[0],
        "total_cancel_requests": conn.execute("SELECT COUNT(*) FROM cancellation_requests").fetchone()[0],
        "pending_cancellations": conn.execute("SELECT COUNT(*) FROM cancellation_requests WHERE status='pending'").fetchone()[0],
        "approved_cancellations": conn.execute("SELECT COUNT(*) FROM cancellation_requests WHERE status='approved'").fetchone()[0],
        "rejected_cancellations": conn.execute("SELECT COUNT(*) FROM cancellation_requests WHERE status='rejected'").fetchone()[0],
        "revenue": conn.execute("SELECT COALESCE(SUM(amount), 0) FROM payments WHERE status='paid'").fetchone()[0],
        "plan_stats": conn.execute("""SELECT p.name, p.price, p.billing_cycle, p.status, COUNT(CASE WHEN s.status IN ('active','canceling') THEN 1 END) as active_count, COUNT(CASE WHEN s.status='expired' THEN 1 END) as expired_count, COUNT(CASE WHEN s.status IN ('canceled','canceling') THEN 1 END) as canceled_count, COUNT(s.id) as total_subs FROM plans p LEFT JOIN subscriptions s ON p.id = s.plan_id GROUP BY p.id ORDER BY active_count DESC""").fetchall(),
        "recent_users": conn.execute("SELECT name, email, created_at FROM users WHERE role='user' ORDER BY id DESC LIMIT 5").fetchall(),
        "recent_payments": conn.execute("SELECT pay.*, u.name as user_name FROM payments pay JOIN users u ON pay.user_id=u.id ORDER BY pay.id DESC LIMIT 8").fetchall(),
    }
    conn.close(); return data


@app.route("/admin/reports/export/pdf")
@admin_required
def export_reports_pdf():
    data = build_report_data()
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
        from reportlab.lib.units import inch
        import io
        buffer = io.BytesIO(); pdf = canvas.Canvas(buffer, pagesize=letter); width, height = letter; y = height - inch
        pdf.setFont("Helvetica-Bold", 16); pdf.drawString(inch, y, "Substra Learn Reports"); y -= 24
        pdf.setFont("Helvetica", 10); pdf.drawString(inch, y, f"Generated: {now_str()}"); y -= 28
        pdf.setFont("Helvetica-Bold", 12); pdf.drawString(inch, y, "Summary"); y -= 18
        pdf.setFont("Helvetica", 10)
        summary = [("Total Users", data["total_users"]), ("Total Paid Revenue", f"PHP {data['revenue']:.2f}"), ("Active Subscriptions", data["active_subs"]), ("Canceled/Canceling", data["canceled_subs"]), ("Pending Cancellations", data["pending_cancellations"])]
        for label, value in summary:
            pdf.drawString(inch, y, f"{label}: {value}"); y -= 16
        y -= 10; pdf.setFont("Helvetica-Bold", 12); pdf.drawString(inch, y, "Plan Performance"); y -= 18; pdf.setFont("Helvetica", 9)
        for p in data["plan_stats"]:
            if y < inch: pdf.showPage(); y = height - inch; pdf.setFont("Helvetica", 9)
            pdf.drawString(inch, y, f"{p['name']} - {p['billing_cycle']} - Active: {p['active_count']} Expired: {p['expired_count']} Canceled: {p['canceled_count']} Total: {p['total_subs']}"); y -= 14
        pdf.save(); buffer.seek(0)
        response = make_response(buffer.read()); response.headers["Content-Type"] = "application/pdf"; response.headers["Content-Disposition"] = "attachment; filename=substra_learn_report.pdf"; return response
    except Exception as e:
        flash(f"PDF export failed: {e}. Install reportlab with pip install -r requirements.txt.", "danger")
        return redirect("/admin/reports")


if __name__ == "__main__":
    app.run(debug=True, port=5001)
