# OpsPilot API

OpsPilot is a FastAPI backend using SQLAlchemy's async ORM, PostgreSQL, and
Redis. Start PostgreSQL and Redis, configure `.env`, and apply database
migrations before starting the API:

```sh
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
docker run --name opspilot-redis -p 6379:6379 -d redis:7-alpine
alembic upgrade head
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Set `DATABASE_URL` to a PostgreSQL SQLAlchemy URL, for example
`postgresql+asyncpg://...`. `REDIS_URL` defaults to `redis://localhost:6379`.
The API checks Redis and PostgreSQL on startup and closes Redis cleanly on
shutdown. Redis stores expiring OTP state and rate-limit counters; PostgreSQL
stores accounts, project memberships, and hashed refresh sessions. Check
`GET /health/ready` for PostgreSQL and Redis readiness.

Do not commit `.env` or use the example values as production credentials.
Generate each signing/pepper secret independently with:

```sh
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Configure SMTP (`SMTP_HOST`, `SMTP_FROM`, and either STARTTLS or implicit TLS)
before using registration, login, or password reset. The canonical username
setting is `SMTP_USER`; `SMTP_USERNAME` remains an accepted environment
variable alias. SMTP credentials must be provided together. The service does
not log OTPs or credentials, and does not fall back to logging verification
codes when email is unavailable. Configure comma-separated `FRONTEND_ORIGINS`
for credentialed browser CORS. For a cross-site frontend, configure
`REFRESH_COOKIE_SAMESITE=none` and keep `REFRESH_COOKIE_SECURE=true`. The
refresh cookie is Secure by default; only disable it for local HTTP testing.

For Brevo, authenticate the exact `SMTP_FROM` domain in Brevo and publish the
SPF and DKIM records shown in its domain settings. Merge Brevo's SPF mechanism
into the domain's existing SPF record; do not publish multiple SPF records.
Keep DMARC alignment in mind, especially when the domain's DMARC policy uses
`p=quarantine` or `p=reject`.

## Authentication API

All request and response bodies are JSON. Email addresses are normalized
before storage and comparisons.

| Endpoint | Purpose |
| --- | --- |
| `POST /auth/register` | Begin public registration; accepts `email`, `display_name`, and `password`. Responds `202` generically and emails an OTP. Registration creates no project access. |
| `POST /auth/register/verify` | Accepts `email` and six-digit `code`; activates the account after email verification and returns tokens. |
| `POST /auth/login` | Accepts `email` and `password`; returns a generic response and sends an OTP for valid credentials. |
| `POST /auth/login/verify` | Accepts `email` and `code`; returns tokens after successful OTP verification. |
| `POST /auth/otp/resend` | Resends a challenge for `register`, `login`, or `reset`, subject to rate limits. `registration`, `password_reset`, and `forgot_password` are aliases. Resending replaces the previous code. |
| `POST /auth/password/reset` | Begin a non-enumerating password reset request. |
| `POST /auth/password/reset/verify` | Verifies an emailed OTP and returns a short-lived, single-use `reset_token`. |
| `POST /auth/password/reset/complete` | Accepts `reset_token` and `new_password`; updates the password and revokes refresh sessions. |
| `POST /auth/password/change` | Requires a bearer access token and `current_password` plus `new_password`; revokes refresh sessions. |
| `POST /auth/refresh` | Rotates the refresh session and returns a new access token. The refresh token is read only from the cookie. |
| `POST /auth/logout` | Revokes the current refresh session, if present, and clears its cookie. |
| `GET /auth/me` | Returns the verified profile and accessible projects with project roles; requires a bearer access token. |

Access tokens are short-lived JWTs returned in the JSON body and sent as a
bearer authorization header. Refresh tokens use a separate signing secret, are
stored only as hashes in PostgreSQL, and are set in an `HttpOnly` cookie scoped
to `/auth`. The API never returns refresh tokens in JSON. Each refresh rotates
the token; reuse of a revoked token revokes that token family. Logout revokes
the current refresh session. Already issued access tokens expire naturally
within 15 minutes; logout and password changes do not immediately revoke access
JWTs.

OTP codes expire after `OTP_EXPIRE_MINUTES` (five minutes by default), are
single-use, and allow at most `OTP_MAX_ATTEMPTS` verification attempts. Only an
HMAC hash is held in Redis; the purpose is bound to the challenge and
verification is atomic. Resends are limited by `OTP_MAX_RESENDS` per challenge
and separate per-email/per-IP Redis counters shared across API workers. Defaults
are five minutes, three attempts, and three resends. `OTP_HASH_SECRET_KEY` must
contain at least 32 bytes.

## Project API

Projects are the active ownership and access boundary. Public account
registration creates a user only; it does not create a project or grant access.
Organization and invitation routes, models, and storage have been removed.

| Endpoint | Purpose |
| --- | --- |
| `POST /projects` | Create a project for the authenticated user; the creator becomes its `owner`. |
| `GET /projects` | List only projects where the authenticated user has a project membership. |
| `GET /projects/{project_id}` | Retrieve a project only if the authenticated user is a member. |
| `PATCH /projects/{project_id}` | Update project name or description; only project owners may update. |
| `DELETE /projects/{project_id}` | Delete a project and its memberships/environments; only project owners may delete. |

Project roles are `owner` and `member`. Members can view projects but cannot
update or delete them. Project queries are scoped by the authenticated user's
project membership; a project UUID alone does not grant access. Environments
are project-owned database resources and are deleted with their project. The
environment model exists, but environment-management endpoints and invitation
endpoints are not implemented.

## Current scope

The backend currently provides authentication, project-level ownership and
membership, and environments. Incident and evidence workflows are not yet
implemented. The migration removing the legacy organization and invitation
schema refuses to run while records in those legacy tables remain; it preserves
users, projects, project memberships, and environments. This migration is
irreversible.

## Tests

Install test dependencies with `pip install -r requirements-dev.txt`, then run:

```sh
pytest
```
