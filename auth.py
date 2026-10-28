"""GitHub OAuth login gated by the admin's allowlist + FastAPI auth dependencies."""
import os, secrets
from urllib.parse import urlencode
import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
import crypto, db
from github_client import GitHub

router = APIRouter(prefix="/auth")


def base_url() -> str:
    return os.environ.get("BASE_URL", "http://localhost:8000").rstrip("/")


def can_maintain(user: dict) -> bool:
    return user["role"] in ("maintainer", "admin")


def csrf(request: Request):
    # Custom header can't be sent cross-site without a CORS preflight (which we never allow).
    if request.method not in ("GET", "HEAD", "OPTIONS") and request.headers.get("x-csrf") != "1":
        raise HTTPException(403, "Missing CSRF header")


def current_user(request: Request) -> dict:
    uid = request.session.get("uid")
    user = db.get_user(uid) if uid else None  # re-read every request => removal takes effect instantly
    if not user:
        request.session.clear()
        raise HTTPException(401, "Not signed in")
    return user


def effective_mode(request: Request, user: dict) -> str:
    mode = request.session.get("mode", "contributor")
    if mode == "maintainer" and not can_maintain(user):
        request.session["mode"] = mode = "contributor"
    return mode


def require_admin(user: dict = Depends(current_user)) -> dict:
    if user["role"] != "admin":
        raise HTTPException(403, "Admin only")
    return user


def require_maintainer_mode(request: Request, user: dict = Depends(current_user)) -> dict:
    if not can_maintain(user):
        raise HTTPException(403, "Maintainer access required")
    if effective_mode(request, user) != "maintainer":
        raise HTTPException(403, "Switch to maintainer mode first")
    return user


def gh_for(user: dict) -> GitHub:
    if not user.get("gh_token"):
        raise HTTPException(401, "Sign in again")
    return GitHub(crypto.dec(user["gh_token"]))


@router.get("/login")
def login(request: Request):
    cid = os.environ.get("GITHUB_CLIENT_ID")
    if not cid:
        raise HTTPException(500, "GITHUB_CLIENT_ID is not configured")
    state = secrets.token_urlsafe(24)
    request.session["oauth_state"] = state
    q = urlencode({"client_id": cid, "redirect_uri": f"{base_url()}/auth/callback",
                   "scope": os.environ.get("GITHUB_OAUTH_SCOPE", "public_repo read:user"), "state": state})
    return RedirectResponse(f"https://github.com/login/oauth/authorize?{q}")


@router.get("/callback")
def callback(request: Request, code: str = "", state: str = ""):
    expected = request.session.pop("oauth_state", None)
    if not expected or not code or not secrets.compare_digest(expected, state):
        raise HTTPException(400, "Invalid OAuth state")
    try:
        r = httpx.post("https://github.com/login/oauth/access_token", timeout=15,
                       headers={"Accept": "application/json"},
                       data={"client_id": os.environ["GITHUB_CLIENT_ID"],
                             "client_secret": os.environ["GITHUB_CLIENT_SECRET"],
                             "code": code, "redirect_uri": f"{base_url()}/auth/callback"})
        token = r.json().get("access_token")
        if not token:
            raise HTTPException(400, "GitHub did not return a token")
        gh_user = httpx.get("https://api.github.com/user", timeout=15,
                            headers={"Authorization": f"Bearer {token}"}).json()
    except httpx.HTTPError:
        raise HTTPException(502, "Could not reach GitHub")
    if not db.get_user(gh_user["id"]):  # match on immutable numeric ID, not username
        return RedirectResponse("/?error=not_invited")
    db.record_login(gh_user["id"], gh_user["login"], crypto.enc(token))
    request.session.clear()  # fresh session on login (prevents fixation)
    request.session.update({"uid": gh_user["id"], "mode": "contributor"})
    return RedirectResponse("/")
