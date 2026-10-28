# Issue Solver (multi-user)

## 1. Create a GitHub OAuth App
GitHub → Settings → Developer settings → OAuth Apps → New.
Callback URL: `http://localhost:8000/auth/callback` (use your real domain in production).

## 2. Configure
```
export GITHUB_CLIENT_ID=...
export GITHUB_CLIENT_SECRET=...
export ADMIN_GITHUB_USERNAME=your-github-username   # first admin, seeded on startup
export SESSION_SECRET=$(python -c "import secrets;print(secrets.token_urlsafe(32))")
export ISSUE_SOLVER_MASTER_KEY=$(python -c "from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())")
export BASE_URL=http://localhost:8000
```
Keep `SESSION_SECRET` and `ISSUE_SOLVER_MASTER_KEY` stable. Changing the master key makes stored keys unreadable.

## 3. Run
```
pip install -r requirements.txt
uvicorn main:app --reload
```
Open http://localhost:8000, sign in, add users from the Admin panel.

## Roles
- contributor: sees assigned issues, manages own model keys
- maintainer: can toggle maintainer mode (enforced server-side)
- admin: everything above + manage users and roles

Set `ALLOW_PRIVATE_BASE_URLS=1` only if you need custom model endpoints on a private network (e.g. local Ollama).
