# Issue Solver (multi-user)

Invite-only GitHub app for solving assigned issues, triaging maintainer queues, and drafting replies.
Each user signs in with GitHub, adds their own model key, and runs jobs on the server using that key.

## 1. Create a GitHub OAuth App

GitHub → Settings → Developer settings → OAuth Apps → New.
Callback URL: `http://localhost:8000/auth/callback` (use your real domain in production).

## 2. Configure

Copy `.env.example` and fill it in:

```
export GITHUB_CLIENT_ID=...
export GITHUB_CLIENT_SECRET=...
export ADMIN_GITHUB_USERNAME=your-github-username
export SESSION_SECRET=$(python -c "import secrets;print(secrets.token_urlsafe(32))")
export ISSUE_SOLVER_MASTER_KEY=$(python -c "from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())")
export BASE_URL=http://localhost:8000
```

Keep `SESSION_SECRET` and `ISSUE_SOLVER_MASTER_KEY` stable. Changing the master key makes stored keys and
GitHub tokens unreadable.

## 3. Run

```
pip install -r requirements.txt
set -a; . ./.env; set +a
uvicorn main:app --reload
```

Open http://localhost:8000, sign in, and add users from the Admin panel.

## Roles

| Role | Can do |
| --- | --- |
| contributor | See assigned issues, run the solver, manage own model keys |
| maintainer | Everything above, plus maintainer mode: triage labels and draft replies |
| admin | Everything above, plus manage users, roles, and view the audit log |

The maintainer toggle is enforced server-side. Hiding it in the UI is only cosmetic.

## Server-side solver

Jobs run in the backend using the submitting user's encrypted model key. The server sends issue content to
the selected provider, so users confirm per run. Results are drafts only; nothing is posted to GitHub.

- `solve` — implementation plan and optional diff for an assigned issue
- `triage` — up to 5 labels chosen from the repo's existing labels (maintainer mode)
- `reply` — draft public reply (maintainer mode)

Triage labels are applied only when the maintainer clicks **Apply selected labels**, and the server checks
write access and that every label already exists. The solver does not execute code, open pull requests, or
post replies automatically.

Limits (environment variables):

```
LLM_MAX_TOKENS=1200
LLM_TIMEOUT=120
MAX_ISSUE_CHARS=20000
MAX_JOBS_PER_HOUR=20
MAX_ACTIVE_JOBS=2
MAX_KEYS_PER_USER=10
SOLVER_WORKERS=2
```

Run a single Uvicorn worker. Jobs are executed in-process, and the SQLite queue is not designed for
multiple app processes.

## Security notes

- Allowlisted by immutable GitHub numeric ID, so renamed or reclaimed usernames cannot inherit access.
- Every request re-reads the user from the database; removing or demoting someone takes effect immediately.
- GitHub OAuth state check, fresh session on login, `SameSite=Lax` cookies, CSRF header on every write.
- API keys and GitHub tokens are encrypted at rest with Fernet.
- Custom model URLs must be public HTTPS (SSRF guard). `ALLOW_PRIVATE_BASE_URLS=1` is the opt-out for
  local models. The guard does not stop DNS rebinding; use an egress firewall if hosted publicly.
- Issue titles and model output are escaped; the page serves a strict CSP.
- Admin safeguards prevent removing or demoting the last admin or changing your own access.
- Server-side jobs require per-run consent and are rate-limited per user.
- Job inputs and model output are stored in the local SQLite database; treat that file as sensitive.

OAuth scope defaults to `public_repo read:user`. Private repositories require widening it to `repo`, which is
a bigger permission to ask of every user.

## Tests

```
pip install -r requirements-dev.txt
pytest -q
```

CI runs the same suite on push and pull request.

## Docker

```
cp .env.example .env
docker compose up --build
```

The SQLite database and fallback master key live in `/data` (mounted from `./data`).

## Production checklist

- Set a stable `SESSION_SECRET`, `ISSUE_SOLVER_MASTER_KEY`, and `BASE_URL=https://...`.
- Put the app behind TLS (reverse proxy) and set `BASE_URL` to the HTTPS URL.
- Back up the SQLite database and master key together.
- Keep `ADMIN_GITHUB_USERNAME` set so the bootstrap admin is restored on startup.
