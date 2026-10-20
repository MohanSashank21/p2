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
Generate each signing/pepper secret independently with:

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
| `POST /auth/otp/resend` | Accepts `email` and `purpose` (`register`, `login`, or `reset`) to resend the active code, subject to limits. `registration`, `password_reset`, and `forgot_password` are accepted aliases for `register` and `reset`. Resending replaces the previous code; use only the newest email's code. Resend returns the same generic `202` response whether or not a challenge exists, to avoid revealing account or challenge state. If the challenge expired or no email arrives, restart the corresponding flow (for login, submit the email and password again). |
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

OTP codes expire after `OTP_EXPIRE_MINUTES` (five minutes by default), are single-use, and allow at most
`OTP_MAX_ATTEMPTS` verification attempts. Only an HMAC hash is held in Redis;
the purpose is bound to the challenge and verification is atomic. Resends are
limited by `OTP_MAX_RESENDS` per challenge and separate per-email/per-IP Redis
counters shared across API workers. Defaults are five minutes, three attempts,
and three resends.
`OTP_HASH_SECRET_KEY` must contain at least 32 bytes.

## Organization access

Public account registration creates a verified user only. It does not create
an organization, project, or membership, and cannot assign a role. An
authenticated user creates an organization explicitly through
`POST /organisations`.

`POST /organisations` creates an organization for the authenticated user and
stores the authenticated user's ID in `organisations.owner_user_id` and creates
that user's `owner` membership in the same transaction. The database enforces
that this column and the owner membership identify the same user. Organization
names must contain 1-120 non-whitespace characters. `GET /organisations`
returns only organizations where the authenticated user has a membership,
including the owner user ID. A user may create and belong to multiple
organizations. Organization membership roles are `owner` and `member`; these
roles are separate from project roles. The database prevents duplicate
user-organization memberships, multiple owners, and committing an organization
without its declared owner.

An organization owner proposes a project and invites a verified organization
member to manage it through `POST /organisations/{organisation_id}/projects`,
providing the project name, optional description, and `manager_user_id`. The
invitation request and database use the user's ID; the service looks up the
verified account's email address only to deliver the message. The project is
created only after that person accepts the email invitation through
`POST /project-invitations/accept`. Invitations expire after seven days, are
bound to the invited account, and can only be accepted once. Invitation API
responses contain a short message and numeric `expires_in` value.

Project roles are `manager` and `worker`, stored separately from organization
roles. An organization owner sees every created project. A member sees only
projects they have accepted an invitation to join. A project manager invites an
existing verified organization member as a worker through
`POST /organisations/{organisation_id}/projects/{project_id}/worker-invitations`;
provide the member's `user_id`; the service looks up their email for delivery.
The worker receives project access only after accepting the invitation.
Managers cannot assign another manager. Project memberships must belong to the
same organization as their project, and the database prevents duplicate
user-project memberships. Fine-grained worker actions are not defined yet;
project roles currently control project visibility and who may invite workers.
A person may have different project roles in the same organization. When an
organization owner also accepts a project invitation, the project listing
returns that explicit project role for that project while the owner retains
organization-wide access.

An environment is a project-specific target such as Development, Staging, or
Production, optionally with a base URL. The current API has the environment
database model but does not yet provide environment-management endpoints.

Owners can invite any email address through
`POST /organisations/{organisation_id}/invitations` with the `member` role.
Invitations to existing members are rejected. Repeating the request for a
pending invitation sends a fresh link and invalidates the previous link. The
recipient can sign up if needed, but must verify and sign in with the invited
email before explicitly accepting through
`POST /organisations/invitations/accept`. Invitations expire after seven days.
Invitation links use `FRONTEND_BASE_URL` and require a reachable frontend with
an `/accept-invitation` route; `localhost` links only work on the machine
running that frontend. The accept API also requires an access token for the
invited email, not merely access to the email inbox.
There is no public endpoint that can grant an owner or project role without an
authenticated organization-creation request or invitation acceptance.
Organization names are globally unique, ignoring surrounding whitespace and
letter case. Creating an organization with a name already in use returns
`409 Conflict`.

## Database migration impact

The authentication migrations add `users.email_verified` with a false default
and refresh-session and invitation storage.
The organization ownership migration normalizes existing `admin` and `worker`
memberships and invitation roles to `member`, then enforces the `owner` and
`member` role set and database ownership constraints. Before applying it, every
existing organization must already have exactly one owner membership; the
migration fails with a clear error rather than guessing who should own an
organization. A later migration stores that owner's user ID on the
organization row and enforces that it matches the owner membership. The
project-membership migration adds project-scoped manager and worker assignments
and constraints ensuring the assigned user is an organization member.
Project-invitation storage records invitee IDs rather than copied email
addresses. Existing accounts require verified email before they can
authenticate.

## Planned feature: in-app invitations

The current project invitation endpoints accept user IDs and require existing,
verified organization members. Invitations are delivered by email; the current
API does not provide an in-app invitation inbox or notification center.

Future implementation should allow an organization owner to invite a project
manager by email while proposing a project, and allow a project manager to
invite workers by email. Store pending invitations so recipients can find them
in an authenticated in-app Invitations view after signing in or completing
signup. Provide actions to accept or decline; accepting must verify that the
signed-in account owns the invited, verified email address and only then grant
the corresponding project role (and create the proposed project for a manager
invitation). Merely receiving an email or seeing a notification must never
grant access. Keep email links as an entry point to the same pending invitation
flow, and preserve expiration, one-time acceptance, and secure token handling.

## Tests

Install test dependencies with `pip install -r requirements-dev.txt`, then run:

```sh
pytest
```
