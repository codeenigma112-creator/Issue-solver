"""GitHub OAuth login gated by the admin's allowlist + FastAPI auth dependencies."""
import logging, os, secrets
from urllib.parse import urlencode
import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
import crypto, db
from github_client import GitHub

log = logging.getLogger("issue_solver.auth")
router = APIRouter(prefix="/auth")


def base_url() -> str:
    return os.environ.get("BASE_URL", "http://localhost:8000").rstrip("/")


def can_maintain(user: dict) -> bool:
    return user["role"] in ("maintainer", "admin")


def csrf(request: Request):
    # Custom header can't be sent cross-site without a CORS preflight (which we never allow).
    if request.method not in ("GET", "HEAD", "OPTIONS") and request.headers.get("x-csrf") != "1":
        raise HTTPException(403, "Missing CSRF header")


def session_user(request: Request) -> dict | None:
    """The signed-in user, or None. The cookie is signed but stateless, so it also carries the
    user's session_epoch; logout bumps the epoch, which kills every copy of the old cookie."""
    uid = request.session.get("uid")
    user = db.get_user(uid) if uid else None  # re-read every request => removal takes effect instantly
    if user and request.session.get("epoch") != user["session_epoch"]:
        return None
    return user


def current_user(request: Request) -> dict:
    user = session_user(request)
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


def revoke_github_token(enc_token: str | None) -> None:
    """Best-effort: invalidate the OAuth token at GitHub itself, not just forget it locally."""
    cid, secret = os.environ.get("GITHUB_CLIENT_ID"), os.environ.get("GITHUB_CLIENT_SECRET")
    if not (enc_token and cid and secret):
        return
    try:
        httpx.request("DELETE", f"https://api.github.com/applications/{cid}/token", timeout=10,
                      auth=(cid, secret), headers={"Accept": "application/vnd.github+json"},
                      json={"access_token": crypto.dec(enc_token)})
    except Exception:  # never block logout / removal on GitHub being unreachable
        log.warning("Could not revoke GitHub token", exc_info=True)


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
        r.raise_for_status()
        payload = r.json()
        if not isinstance(payload, dict):
            raise HTTPException(502, "GitHub returned an invalid token response")
        token = payload.get("access_token")
        if not token:
            raise HTTPException(400, payload.get("error_description") or "GitHub did not return a token")
        u = httpx.get("https://api.github.com/user", timeout=15,
                      headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"})
        u.raise_for_status()
        gh_user = u.json()
    except httpx.HTTPError:
        raise HTTPException(502, "Could not reach GitHub")
    except ValueError:
        raise HTTPException(502, "GitHub returned an invalid response")
    if not isinstance(gh_user, dict) or not gh_user.get("id") or not gh_user.get("login"):
        raise HTTPException(502, "GitHub returned an invalid user")
    if not db.get_user(gh_user["id"]):  # match on immutable numeric ID, not username
        # First-run bootstrap: if no admin exists yet and GitHub just verified that the person signing
        # in is ADMIN_GITHUB_USERNAME, make them the admin. Needs no GitHub lookup, so it can't fail
        # on rate limits the way the startup seeding can.
        boot = os.environ.get("ADMIN_GITHUB_USERNAME", "").strip().lstrip("@").lower()
        if boot and gh_user["login"].lower() == boot and db.count_admins() == 0:
            db.add_user(gh_user["id"], gh_user["login"], "admin", "bootstrap")
            db.audit(None, "admin.bootstrap", target=str(gh_user["id"]), detail=str(gh_user["login"]))
        else:
            db.audit(None, "login.denied", target=str(gh_user["id"]), detail=str(gh_user["login"]))
            return RedirectResponse("/?error=not_invited")
    db.record_login(gh_user["id"], gh_user["login"], crypto.enc(token))
    user = db.get_user(gh_user["id"])
    db.audit(user, "login")
    request.session.clear()  # fresh session on login (prevents fixation)
    request.session.update({"uid": gh_user["id"], "mode": "contributor", "epoch": user["session_epoch"]})
    return RedirectResponse("/")
