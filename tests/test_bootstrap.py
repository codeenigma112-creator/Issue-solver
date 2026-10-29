"""First sign-in of ADMIN_GITHUB_USERNAME creates the admin without any GitHub lookup."""
import base64, json, random

import pytest
from fastapi.testclient import TestClient
from itsdangerous import TimestampSigner

import auth, db, main


class FakeResp:
    def __init__(self, data): self._d = data
    def raise_for_status(self): pass
    def json(self): return self._d


def sign_in(monkeypatch, login, gid, admins):
    monkeypatch.setenv("GITHUB_CLIENT_ID", "cid"); monkeypatch.setenv("GITHUB_CLIENT_SECRET", "sec")
    monkeypatch.setenv("ADMIN_GITHUB_USERNAME", "@MyAdmin")
    monkeypatch.setattr(db, "count_admins", lambda: admins)
    monkeypatch.setattr(auth.httpx, "post", lambda *a, **k: FakeResp({"access_token": "gho_x"}))
    monkeypatch.setattr(auth.httpx, "get", lambda *a, **k: FakeResp({"id": gid, "login": login}))
    c = TestClient(main.app)
    raw = base64.b64encode(json.dumps({"oauth_state": "s1"}).encode())
    c.cookies.set("session", TimestampSigner("test-session-secret").sign(raw).decode())
    return c, c.get("/auth/callback?code=abc&state=s1", follow_redirects=False)


def test_first_login_of_configured_admin_becomes_admin(monkeypatch):
    db.init(); gid = random.randint(10**9, 10**10)
    c, r = sign_in(monkeypatch, "myadmin", gid, admins=0)       # case-insensitive match
    assert r.status_code in (302, 307) and r.headers["location"] == "/"
    assert db.get_user(gid)["role"] == "admin"
    me = c.get("/api/me").json()
    assert me["role"] == "admin" and me["can_maintain"] is True


def test_no_bootstrap_when_an_admin_already_exists(monkeypatch):
    db.init(); gid = random.randint(10**9, 10**10)
    _, r = sign_in(monkeypatch, "MyAdmin", gid, admins=1)
    assert r.headers["location"] == "/?error=not_invited" and db.get_user(gid) is None


def test_other_people_are_still_denied(monkeypatch):
    db.init(); gid = random.randint(10**9, 10**10)
    _, r = sign_in(monkeypatch, "someone-else", gid, admins=0)
    assert r.headers["location"] == "/?error=not_invited" and db.get_user(gid) is None
