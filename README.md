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
the selected provider, so users confirm per run.

- `solve` — reads the repository, asks the model for complete file edits, pushes a branch, and opens a pull
  request for review. With write access the branch is created in the repository; otherwise the app forks the
  repository and opens a cross-repository pull request. After opening the PR it waits for CI and, if checks
  fail, asks the model to fix them and pushes follow-up commits, repeating up to `SOLVE_CI_FIX_ATTEMPTS`
  times or until all checks are green.
- `triage` — up to 5 labels chosen from the repo's existing labels (maintainer mode)
- `reply` — draft public reply (maintainer mode)

Triage labels are applied only when the maintainer clicks **Apply selected labels**, and the server checks
write access and that every label already exists. Reply drafts are never posted automatically. Pull request
CI runs after the PR is opened; the app does not execute repository code or test commands on the server.

Limits (environment variables):

```
LLM_MAX_TOKENS=1200
LLM_TIMEOUT=120
LLM_RETRIES=2
LLM_RETRY_DELAY=2
MAX_ISSUE_CHARS=20000
SOLVE_MAX_TOKENS=8000
SOLVE_MAX_FILES=12
SOLVE_MAX_FILE_CHARS=30000
SOLVE_MAX_CONTEXT_CHARS=120000
SOLVE_MAX_TREE_CHARS=30000
SOLVE_MAX_EDITS=10
SOLVE_MAX_EDITED_CHARS=200000
SOLVE_MAX_PATCH_CHARS=300000
SOLVE_ISSUE_CHARS=12000
SOLVE_FORK_TIMEOUT=60
SOLVE_CI_WAIT=300
SOLVE_CI_POLL=20
SOLVE_CI_FIX_ATTEMPTS=3
MAX_JOBS_PER_HOUR=20
MAX_ACTIVE_JOBS=2
MAX_KEYS_PER_USER=10
SOLVER_WORKERS=2
JOB_RETENTION_DAYS=30
AUDIT_RETENTION_DAYS=180
```

Finished jobs and audit rows older than the retention windows are deleted automatically (`0` keeps them forever).

Run a single Uvicorn worker. Jobs are executed in-process, and the SQLite queue is not designed for
multiple app processes.

## Security notes

- Allowlisted by immutable GitHub numeric ID, so renamed or reclaimed usernames cannot inherit access.
- Every request re-reads the user from the database; removing or demoting someone takes effect immediately.
- Sign out invalidates the session cookie server-side (per-user session epoch) and revokes the GitHub OAuth token at GitHub.
- Per-user job limits are checked and enforced in a single database transaction, so parallel requests can't exceed them.
- GitHub OAuth state check, fresh session on login, `SameSite=Lax` cookies, CSRF header on every write.
- API keys and GitHub tokens are encrypted at rest with Fernet.
- Custom model URLs must be public HTTPS (SSRF guard). `ALLOW_PRIVATE_BASE_URLS=1` is the opt-out for
  local models. The guard does not stop DNS rebinding; use an egress firewall if hosted publicly.
- Issue titles and model output are escaped; the page serves a strict CSP.
- Admin safeguards prevent removing or demoting the last admin or changing your own access.
- Server-side jobs require per-run consent and are rate-limited per user.
- Solve commits model-generated code only to a new branch and opens a pull request; review every change before
  merging. Edits to CI/workflow, lockfile, and credential files are rejected, and repository tests are not run
  on the server. CI failures are fixed by further model-generated commits on the same branch; review those too.
- Job inputs and model output are stored in the local SQLite database; treat that file as sensitive.

OAuth scope defaults to `public_repo read:user`, which is enough to fork and open pull requests against public
repositories. Private repositories require widening it to `repo`, which is a bigger permission to ask of every user.

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
