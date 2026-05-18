# Substra Learn Updated

This is the updated ready-made Flask project based on the uploaded files.

## Added features

1. Registration password rule: at least 8 characters, shown above the password field.
2. Live red confirm-password warning that disappears when passwords match.
3. Email OTP verification before account creation.
4. University field during registration.
5. Admin notifications when a user requests cancellation.
6. User notifications when a cancellation request is approved or rejected.
7. Approved cancellations remain usable until the subscription expiration date, then auto-cancel.
8. Free Trial plan that expires after 7 days.
9. Reports export to PDF from the admin reports page.
10. Automatic lesson progress based on scroll percentage plus whole-course percentage.
11. More detailed sample lessons.
12. Local Resend SMTP test script before deployment.

## Local setup

```bash
python -m venv .venv

# Windows PowerShell:
.venv\Scripts\Activate.ps1

# Windows CMD:
.venv\Scripts\activate.bat

# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
copy .env.example .env  # Windows
# or: cp .env.example .env

python createdb.py
python create_admin.py
python app.py
```

Open:

```text
http://127.0.0.1:5001
```

Default admin from `.env.example`:

- Email: `admin@gmail.com`
- Password: `admin12345`

Change these in `.env` before using the app seriously.

## Local OTP testing options

### Option A: Easy local flow, no real email

Keep this in `.env`:

```env
EMAIL_DEV_MODE=true
```

The app will show the OTP on screen and print it in the terminal. This is best for quickly testing the registration flow.

### Option B: Real local email using Resend SMTP

Use this when you want to confirm real email sending before deploying to Render.

1. Create a Resend API key.
2. Edit `.env` like this:

```env
EMAIL_DEV_MODE=false
SMTP_HOST=smtp.resend.com
SMTP_PORT=587
SMTP_USE_TLS=true
SMTP_USE_SSL=false
SMTP_USER=resend
SMTP_PASSWORD=re_your_real_resend_api_key_here
MAIL_FROM=onboarding@resend.dev
MAIL_FROM_NAME=Substra Learn
TEST_EMAIL_TO=your_email@gmail.com
```

3. Test Resend without Flask:

```bash
python test_resend_email.py
```

Or:

```bash
python test_resend_email.py your_email@gmail.com
```

4. If the test email arrives, run the app and register a test user.

For local school-demo testing, `MAIL_FROM=onboarding@resend.dev` is okay. If Resend blocks messages to other recipients, try sending to your own Resend account email first. For real production later, verify your own domain in Resend and use something like `no-reply@yourdomain.com`.

Resend SMTP uses host `smtp.resend.com`, username `resend`, and your API key as the password.

## Render deployment environment variables

Set these in Render > your web service > Environment:

```env
EMAIL_DEV_MODE=false
SMTP_HOST=smtp.resend.com
SMTP_PORT=587
SMTP_USE_TLS=true
SMTP_USE_SSL=false
SMTP_USER=resend
SMTP_PASSWORD=your_resend_api_key
MAIL_FROM=onboarding@resend.dev
MAIL_FROM_NAME=Substra Learn
```

Also set your Flask/database/admin/Stripe variables as needed.

## Important security note

Do not commit real Stripe keys, webhook secrets, Resend API keys, or production passwords. This bundle includes `.env.example` only.
