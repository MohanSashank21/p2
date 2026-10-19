# OpsPilot API

This service uses FastAPI, SQLAlchemy's async ORM, PostgreSQL, and Redis. Start
PostgreSQL and Redis, configure `.env`, and apply database migrations before
starting the API:

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
The API opens one async Redis client during lifespan, checks Redis and
PostgreSQL on startup, and closes Redis cleanly on shutdown. Redis holds only
expiring OTP state and rate-limit counters; PostgreSQL remains the persistent
store for accounts, memberships, and hashed refresh sessions. Check readiness
at `GET /health/ready`; it reports only whether PostgreSQL and Redis are
reachable.

Do not commit `.env` or use the example values as production credentials.
Generate each signing/pepper/bootstrap secret independently with:

```sh
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Configure SMTP (`SMTP_HOST`, `SMTP_FROM`, and either STARTTLS or implicit TLS)
before using registration, login, password reset, or invitations. The canonical
username setting is `SMTP_USER`; `SMTP_USERNAME` remains an accepted
environment-variable alias. SMTP credentials must be provided together. The
service does not log OTPs, invitation tokens, or credentials, and does not fall
back to logging verification codes when email is unavailable. Configure
`FRONTEND_BASE_URL` for invitation links and comma-separated `FRONTEND_ORIGINS`
for credentialed browser CORS. For a cross-site frontend, configure
`REFRESH_COOKIE_SAMESITE=none` and keep `REFRESH_COOKIE_SECURE=true`. The
refresh cookie is Secure by default; only disable it for local HTTP testing.

## Authentication API

All request and response bodies are JSON. Email addresses are normalized before
storage and comparisons.

| Endpoint | Purpose |
| --- | --- |
| `POST /auth/register` | Begin public registration; accepts `email`, `display_name`, and `password`. Responds `202` with a generic message and emails an OTP. This does not create an active account or organization membership. |
| `POST /auth/register/verify` | Accepts `email` and six-digit `code`; activates the account only after a valid email code and returns tokens. |
| `POST /auth/login` | Accepts `email` and `password`; returns the same generic response regardless of credential validity. A valid login sends an OTP. |
| `POST /auth/login/verify` | Accepts `email` and `code`; returns tokens after successful OTP verification. |
| `POST /auth/otp/resend` | Accepts `email` and `purpose` (`register`, `login`, or `reset`) to resend the active code, subject to limits. `registration`, `password_reset`, and `forgot_password` are accepted aliases for `register` and `reset`. Returns the same generic `202` response whether or not a challenge exists, to avoid revealing account or challenge state; restart the corresponding flow if no code arrives. |
| `POST /auth/password/reset` | Begin a non-enumerating password reset request. |
| `POST /auth/password/reset/verify` | Accepts `email` and `code`; verifies the OTP and returns a short-lived, single-use `reset_token`. |
| `POST /auth/password/reset/complete` | Accepts `reset_token` and `new_password`; updates the password and revokes all refresh sessions. |
| `POST /auth/password/change` | Requires a bearer access token and `current_password` plus `new_password`; revokes all refresh sessions. |
| `POST /auth/refresh` | Rotates the refresh session and returns a new access token. The refresh token is read only from the cookie. |
| `POST /auth/logout` | Revokes the current refresh session, if present, and clears its cookie. |
| `GET /auth/me` | Returns the verified profile and that user's organization memberships; requires a bearer access token. |

Access tokens are short-lived JWTs returned in the JSON body and should be sent
as a bearer authorization header. Refresh tokens are signed with a separate
secret, stored only as hashes in PostgreSQL, and set in an `HttpOnly` cookie
scoped to `/auth`. The cookie is Secure by default; the API never returns the
refresh token in JSON. Each refresh rotates the token; reuse of a revoked token
revokes that refresh-token family. Logout revokes the current refresh session.
Already issued access tokens expire naturally within 15 minutes; logout and
password changes do not immediately revoke access JWTs.

OTP codes expire after `OTP_EXPIRE_MINUTES`, are single-use, and allow at most
`OTP_MAX_ATTEMPTS` verification attempts. Only an HMAC hash is held in Redis;
the purpose is bound to the challenge and verification is atomic. Resends are
limited by `OTP_MAX_RESENDS` per challenge and separate per-email/per-IP Redis
counters shared across API workers. Defaults are five minutes, three attempts,
and three resends.
`OTP_HASH_SECRET_KEY` must contain at least 32 bytes.

## Organization access

Public account registration creates a verified user only. It does not create
an organization, project, or membership, and cannot assign a role. To establish
the first organization, a verified user must call
`POST /organisations/bootstrap` with a valid bearer access token, an
`X-Platform-Bootstrap-Token` matching the one-time `PLATFORM_BOOTSTRAP_TOKEN`
environment secret, and a JSON body such as `{"name":"Example"}`. Bootstrap can
complete only once; leave the token unset to disable this operation after
initial provisioning.

The organization roles are `owner`, `admin`, and `worker`. Role checks are
scoped to the requested organization. Owners and admins can invite existing,
email-verified platform accounts through
`POST /organisations/{organisation_id}/invitations`; owners may invite admins or
workers, while admins may invite workers only. Invitations to unknown accounts,
existing members, and users with a pending invitation are rejected. An
invitation does not grant membership until the recipient signs in to the
verified account with the invited email and explicitly accepts it through
`POST /organisations/invitations/accept`. Invitations expire after seven days.
There is no public endpoint that can grant an owner or project role without the
bootstrap secret or an authorized invitation.

## Database migration impact

The authentication migration adds `users.email_verified` with a false default,
refresh-session and invitation storage, and one-time platform bootstrap state.
It changes legacy `member` and `viewer` membership roles to `worker` before
restricting membership roles to `owner`, `admin`, and `worker`. Existing
accounts therefore require a verified-email process before they can authenticate.
The configured PostgreSQL database had no user or membership rows when this
migration was applied here.

## Tests

Install test dependencies with `pip install -r requirements-dev.txt`, then run:

```sh
pytest
```
