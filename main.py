"""Run: uvicorn main:app --reload"""
import json, logging, os, secrets, sqlite3
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal
import httpx
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.sessions import SessionMiddleware

import auth, crypto, db, providers, solver
from auth import (can_maintain, csrf, current_user, effective_mode, gh_for, require_admin,
                  require_maintainer_mode)
import github_client
from github_client import GitHub, valid_repo

log = logging.getLogger("issue_solver")
STATIC = Path(__file__).parent / "static"
MAX_JOBS_PER_HOUR = int(os.environ.get("MAX_JOBS_PER_HOUR", "20"))
MAX_ACTIVE_JOBS = int(os.environ.get("MAX_ACTIVE_JOBS", "2"))
MAX_KEYS_PER_USER = int(os.environ.get("MAX_KEYS_PER_USER", "10"))
JOB_RETENTION_DAYS = int(os.environ.get("JOB_RETENTION_DAYS", "30"))      # 0 = keep forever
AUDIT_RETENTION_DAYS = int(os.environ.get("AUDIT_RETENTION_DAYS", "180"))  # 0 = keep forever


def seed_admin():
    login = os.environ.get("ADMIN_GITHUB_USERNAME", "").strip().lstrip("@")
    if not login:
        log.warning("ADMIN_GITHUB_USERNAME not set; no admin will be seeded")
        return
    try:
        info = GitHub().user_by_login(login)
    except Exception:
        log.exception("Could not reach GitHub to resolve admin %s", login)
        return
    if not info:
        log.error("Could not resolve admin username %s", login)
        return
    if db.get_user(info["id"]):
        db.set_role(info["id"], "admin")
    else:
        db.add_user(info["id"], info["login"], "admin", "bootstrap")


@asynccontextmanager
async def lifespan(app):
    db.init()
    db.fail_stale_jobs()
    db.maybe_purge(JOB_RETENTION_DAYS, AUDIT_RETENTION_DAYS)
    seed_admin()
    yield
    solver.shutdown()
    github_client.close_client()


SECRET = os.environ.get("SESSION_SECRET")
if not SECRET:
    log.warning("SESSION_SECRET not set; sessions reset on every restart")
    SECRET = secrets.token_urlsafe(32)

app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None)
app.add_middleware(SessionMiddleware, secret_key=SECRET, same_site="lax", max_age=7 * 86400,
                   https_only=auth.base_url().startswith("https"))
app.include_router(auth.router)
app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["Content-Security-Policy"] = ("default-src 'self'; style-src 'self' 'unsafe-inline'; "
                                               "frame-ancestors 'none'")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    if auth.base_url().startswith("https"):
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp


@app.exception_handler(httpx.HTTPStatusError)
async def github_error(_, exc: httpx.HTTPStatusError):
    code = exc.response.status_code
    msg = "GitHub token expired or revoked: sign in again" if code == 401 else f"GitHub error {code}"
    return JSONResponse({"detail": msg}, status_code=401 if code == 401 else 502)


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


api = APIRouter(prefix="/api", dependencies=[Depends(csrf)])


# ---------- session / mode ----------
@api.get("/me")
def me(request: Request, user=Depends(current_user)):
    return {"login": user["login"], "role": user["role"], "can_maintain": can_maintain(user),
            "mode": effective_mode(request, user),
            "limits": {"jobs_per_hour": MAX_JOBS_PER_HOUR, "active_jobs": MAX_ACTIVE_JOBS}}


class ModeIn(BaseModel):
    mode: Literal["contributor", "maintainer"]


@api.post("/mode")
def set_mode(body: ModeIn, request: Request, user=Depends(current_user)):
    if body.mode == "maintainer" and not can_maintain(user):
        raise HTTPException(403, "Maintainer access required. Ask the administrator.")
    request.session["mode"] = body.mode
    db.audit(user, "mode.change", detail=body.mode)
    return {"mode": body.mode}


@api.post("/logout")
def logout(request: Request):
    user = auth.session_user(request)  # a stale cookie must not be able to log the real user out
    if user:
        auth.revoke_github_token(user.get("gh_token"))
        db.clear_token(user["github_id"])
        db.bump_session_epoch(user["github_id"])
        db.audit(user, "logout")
    request.session.clear()
    return {"ok": True}


# ---------- model keys (per user) ----------
@api.get("/providers")
def list_providers(user=Depends(current_user)):
    return {k: {"hint": v["hint"], "custom": not v["base_url"]} for k, v in providers.PRESETS.items()}


class KeyIn(BaseModel):
    label: str = Field(min_length=1, max_length=60)
    provider: str
    base_url: str = Field(default="", max_length=300)
    model: str = Field(default="", max_length=120)
    api_key: str = Field(min_length=8, max_length=500)


@api.get("/keys")
def keys(user=Depends(current_user)):
    return [{"id": k["id"], "label": k["label"], "provider": k["provider"], "model": k["model"],
             "api_key": crypto.mask(crypto.dec(k["api_key"]))} for k in db.list_keys(user["github_id"])]


@api.post("/keys")
def add_key(body: KeyIn, user=Depends(current_user)):
    if len(db.list_keys(user["github_id"])) >= MAX_KEYS_PER_USER:
        raise HTTPException(400, f"Key limit reached ({MAX_KEYS_PER_USER})")
    preset = providers.PRESETS.get(body.provider)
    if not preset:
        raise HTTPException(400, "Unknown provider")
    base = preset["base_url"] or body.base_url.strip()
    if not preset["base_url"]:
        try:
            providers.assert_public_https(base)
        except ValueError as e:
            raise HTTPException(400, str(e))
    key = body.api_key.strip()
    ok, msg = providers.validate_key(preset["kind"], base, key)
    if not ok:
        raise HTTPException(400, msg)
    kid = db.add_key(user["github_id"], body.label, body.provider, preset["kind"],
                     base, body.model, crypto.enc(key))
    db.audit(user, "key.add", target=kid, detail=body.provider)
    return {"id": kid, "message": msg}


@api.delete("/keys/{key_id}")
def delete_key(key_id: str, user=Depends(current_user)):
    if not db.delete_key(user["github_id"], key_id):
        raise HTTPException(404, "Not found")
    db.audit(user, "key.delete", target=key_id)
    return {"ok": True}


# ---------- contributor mode ----------
@api.get("/issues")
def my_issues(user=Depends(current_user)):
    return gh_for(user).assigned_issues()


# ---------- jobs ----------
class JobIn(BaseModel):
    kind: Literal["solve", "triage", "reply"]
    repo: str = Field(min_length=3, max_length=140)
    number: int = Field(gt=0, le=2_000_000_000)
    key_id: str = Field(min_length=1, max_length=40)
    instructions: str = Field(default="", max_length=2000)
    consent: bool = False


def _valid_ref(repo: str, number: int):
    if not valid_repo(repo):
        raise HTTPException(400, "Bad repo name")
    if number <= 0 or number > 2_000_000_000:
        raise HTTPException(400, "Bad issue number")


@api.post("/jobs")
def create_job(body: JobIn, request: Request, user=Depends(current_user)):
    if not body.consent:
        raise HTTPException(400, "Confirm that issue content may be sent to your model provider")
    _valid_ref(body.repo, body.number)
    if body.kind in ("triage", "reply"):
        if not can_maintain(user):
            raise HTTPException(403, "Maintainer access required")
        if effective_mode(request, user) != "maintainer":
            raise HTTPException(403, "Switch to maintainer mode first")
    if not db.get_key(user["github_id"], body.key_id):
        raise HTTPException(404, "Model key not found")
    payload = json.dumps({"repo": body.repo, "number": body.number, "key_id": body.key_id,
                          "instructions": body.instructions})
    db.maybe_purge(JOB_RETENTION_DAYS, AUDIT_RETENTION_DAYS)
    jid, blocked = db.create_job_limited(user["github_id"], body.kind, payload,
                                         MAX_JOBS_PER_HOUR, MAX_ACTIVE_JOBS)  # atomic check + insert
    if blocked == "hourly":
        raise HTTPException(429, f"Hourly job limit reached ({MAX_JOBS_PER_HOUR})")
    if blocked == "active":
        raise HTTPException(429, f"Too many running jobs ({MAX_ACTIVE_JOBS})")
    db.audit(user, "job.create", target=jid, detail=f"{body.kind} {body.repo}#{body.number}")
    try:
        solver.submit(jid)
    except RuntimeError:
        db.set_job(jid, "error", error="Job runner is shutting down")
        raise HTTPException(503, "Job runner is shutting down")
    return {"id": jid, "status": "queued"}


@api.get("/jobs")
def jobs(user=Depends(current_user)):
    return db.list_jobs(user["github_id"])


@api.get("/jobs/{job_id}")
def job_detail(job_id: str, user=Depends(current_user)):
    job = db.get_job(job_id, user["github_id"])
    if not job:
        raise HTTPException(404, "Job not found")
    return {"id": job["id"], "kind": job["kind"], "status": job["status"], "result": job["result"],
            "error": job["error"], "created_at": job["created_at"], "updated_at": job["updated_at"]}


# ---------- maintainer mode (role + mode both enforced server-side) ----------
@api.get("/maintainer/repos")
def m_repos(user=Depends(require_maintainer_mode)):
    return gh_for(user).maintained_repos()


@api.get("/maintainer/issues")
def m_issues(repo: str, user=Depends(require_maintainer_mode)):
    if not valid_repo(repo):
        raise HTTPException(400, "Bad repo name")
    gh = gh_for(user)
    if not gh.has_push(repo):
        raise HTTPException(403, "You don't have write access to that repo")
    return gh.unassigned_issues(repo)


class LabelsIn(BaseModel):
    repo: str = Field(min_length=3, max_length=140)
    number: int = Field(gt=0, le=2_000_000_000)
    labels: list[str] = Field(min_length=1, max_length=5)


@api.post("/maintainer/labels")
def m_labels(body: LabelsIn, user=Depends(require_maintainer_mode)):
    _valid_ref(body.repo, body.number)
    labels = list(dict.fromkeys(l.strip() for l in body.labels if l.strip()))[:5]
    if not labels:
        raise HTTPException(400, "No labels selected")
    gh = gh_for(user)
    if not gh.has_push(body.repo):
        raise HTTPException(403, "You don't have write access to that repo")
    allowed = set(gh.repo_labels(body.repo))
    unknown = [l for l in labels if l not in allowed]
    if unknown:
        raise HTTPException(400, "Unknown labels: " + ", ".join(unknown))
    applied = gh.add_labels(body.repo, body.number, labels)
    db.audit(user, "labels.apply", target=f"{body.repo}#{body.number}", detail=", ".join(applied))
    return {"labels": applied}


# ---------- admin ----------
class AddUser(BaseModel):
    username: str = Field(min_length=1, max_length=40)
    role: Literal["contributor", "maintainer", "admin"] = "contributor"


class RoleIn(BaseModel):
    role: Literal["contributor", "maintainer", "admin"]


@api.get("/admin/users")
def admin_list(admin=Depends(require_admin)):
    return db.list_users()


@api.post("/admin/users")
def admin_add(body: AddUser, admin=Depends(require_admin)):
    info = gh_for(admin).user_by_login(body.username.strip().lstrip("@"))
    if not info or info.get("type") != "User":
        raise HTTPException(404, "GitHub user not found")
    try:
        db.add_user(info["id"], info["login"], body.role, admin["login"])
    except sqlite3.IntegrityError:
        raise HTTPException(409, "User already added")
    db.audit(admin, "admin.user.add", target=str(info["id"]), detail=f"{info['login']} {body.role}")
    return {"login": info["login"], "github_id": info["id"]}


def _guard_last_admin(target_id: int, admin: dict):
    t = db.get_user(target_id)
    if not t:
        raise HTTPException(404, "No such user")
    if t["role"] == "admin" and db.count_admins() <= 1:
        raise HTTPException(400, "Can't remove or demote the last admin")
    if target_id == admin["github_id"]:
        raise HTTPException(400, "You can't change your own access")


@api.patch("/admin/users/{github_id}")
def admin_role(github_id: int, body: RoleIn, admin=Depends(require_admin)):
    _guard_last_admin(github_id, admin)
    target = db.get_user(github_id)
    db.set_role(github_id, body.role)
    db.audit(admin, "admin.user.role", target=str(github_id),
             detail=f"{target['login']} {target['role']}->{body.role}")
    return {"ok": True}


@api.delete("/admin/users/{github_id}")
def admin_remove(github_id: int, admin=Depends(require_admin)):
    _guard_last_admin(github_id, admin)
    target = db.get_user(github_id)
    auth.revoke_github_token(target.get("gh_token"))
    db.remove_user(github_id)
    db.audit(admin, "admin.user.remove", target=str(github_id), detail=target["login"])
    return {"ok": True}


@api.get("/admin/audit")
def admin_audit(admin=Depends(require_admin)):
    return db.list_audit()


app.include_router(api)
