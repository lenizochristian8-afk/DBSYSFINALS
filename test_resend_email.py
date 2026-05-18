"""Send a local test email through the configured SMTP provider.

Usage:
    python test_resend_email.py
    python test_resend_email.py your_email@gmail.com

This script reads the same `.env` settings used by app.py.
"""

import os
import sys
import ssl
import smtplib
from email.message import EmailMessage
from dotenv import load_dotenv

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"), override=True)


def env_bool(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).strip().lower() in {"1", "true", "yes", "on"}


def main() -> int:
    to_email = sys.argv[1] if len(sys.argv) > 1 else os.getenv("TEST_EMAIL_TO", "").strip()
    if not to_email:
        print("Missing recipient. Set TEST_EMAIL_TO in .env or run: python test_resend_email.py your_email@gmail.com")
        return 1

    smtp_host = os.getenv("SMTP_HOST", "smtp.resend.com").strip()
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER", "resend").strip()
    smtp_password = os.getenv("SMTP_PASSWORD", "").strip()
    mail_from = os.getenv("MAIL_FROM", "onboarding@resend.dev").strip()
    mail_from_name = os.getenv("MAIL_FROM_NAME", "Substra Learn").strip()
    use_tls = env_bool("SMTP_USE_TLS", "true")
    use_ssl = env_bool("SMTP_USE_SSL", "false")

    if not smtp_password or smtp_password == "re_your_resend_api_key_here":
        print("SMTP_PASSWORD is missing. Put your real Resend API key in .env first.")
        return 1

    msg = EmailMessage()
    msg["Subject"] = "Substra Learn local Resend test"
    msg["From"] = f"{mail_from_name} <{mail_from}>"
    msg["To"] = to_email
    msg.set_content(
        "Hello,\n\n"
        "This is a local SMTP test from your Substra Learn project.\n"
        "If you received this email, OTP sending should work locally too.\n\n"
        "Substra Learn"
    )

    context = ssl.create_default_context()
    try:
        if use_ssl:
            with smtplib.SMTP_SSL(smtp_host, smtp_port, context=context, timeout=20) as server:
                server.login(smtp_user, smtp_password)
                server.send_message(msg)
        else:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=20) as server:
                server.ehlo()
                if use_tls:
                    server.starttls(context=context)
                    server.ehlo()
                server.login(smtp_user, smtp_password)
                server.send_message(msg)
    except Exception as exc:
        print(f"Email test failed: {exc}")
        print("Check your .env values, Resend API key, sender, recipient, and Resend Logs.")
        return 1

    print(f"Success! Test email sent to {to_email}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
