"""Run: uvicorn main:app --reload"""
import logging, os, secrets, sqlite3
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal
import httpx
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.sessions import SessionMiddleware

import auth, crypto, db, providers
from auth import can_maintain, csrf, current_user, effective_mode, gh_for, require_admin, require_maintainer_mode
from github_client import REPO_RE, GitHub

log = logging.getLogger("issue_solver")
STATIC = Path(__file__).parent / "static"


def seed_admin():
    login = os.environ.get("ADMIN_GITHUB_USERNAME", "").strip().lstrip("@")
    if not login:
        log.warning("ADMIN_GITHUB_USERNAME not set; no admin will be seeded")
        return
    info = GitHub().user_by_login(login)
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
    seed_admin()
    yield


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
            "mode": effective_mode(request, user)}


class ModeIn(BaseModel):
    mode: Literal["contributor", "maintainer"]


@api.post("/mode")
def set_mode(body: ModeIn, request: Request, user=Depends(current_user)):
    if body.mode == "maintainer" and not can_maintain(user):
        raise HTTPException(403, "Maintainer access required. Ask the administrator.")
    request.session["mode"] = body.mode
    return {"mode": body.mode}


@api.post("/logout")
def logout(request: Request):
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
    return {"id": db.add_key(user["github_id"], body.label, body.provider, preset["kind"],
                             base, body.model, crypto.enc(key))}


@api.delete("/keys/{key_id}")
def delete_key(key_id: str, user=Depends(current_user)):
    if not db.delete_key(user["github_id"], key_id):
        raise HTTPException(404, "Not found")
    return {"ok": True}


# ---------- contributor mode ----------
@api.get("/issues")
def my_issues(user=Depends(current_user)):
    return gh_for(user).assigned_issues()


# ---------- maintainer mode (role + mode both enforced server-side) ----------
@api.get("/maintainer/repos")
def m_repos(user=Depends(require_maintainer_mode)):
    return gh_for(user).maintained_repos()


@api.get("/maintainer/issues")
def m_issues(repo: str, user=Depends(require_maintainer_mode)):
    if not REPO_RE.match(repo):
        raise HTTPException(400, "Bad repo name")
    gh = gh_for(user)
    if not gh.has_push(repo):
        raise HTTPException(403, "You don't have write access to that repo")
    return gh.unassigned_issues(repo)


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
    db.set_role(github_id, body.role)
    return {"ok": True}


@api.delete("/admin/users/{github_id}")
def admin_remove(github_id: int, admin=Depends(require_admin)):
    _guard_last_admin(github_id, admin)
    db.remove_user(github_id)  # keys cascade-delete; their session dies on next request
    return {"ok": True}


app.include_router(api)
