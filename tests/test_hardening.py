"""Tests for the session, job-limit, retention and token-revocation hardening."""
import base64
import json
import random
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient
from itsdangerous import TimestampSigner

import auth
import crypto
import db
import github_client
import main

SECRET = "test-session-secret"  # matches tests/conftest.py
H = {"X-CSRF": "1"}


@pytest.fixture(autouse=True)
def _db():
    db.init()


def cookie(data: dict) -> str:
    raw = base64.b64encode(json.dumps(data).encode())
    return TimestampSigner(SECRET).sign(raw).decode()


def new_user(role="contributor", token=True):
    gid = random.randint(10**9, 10**10)
    db.add_user(gid, f"user{gid}", role, "test")
    if token:
        db.record_login(gid, f"user{gid}", crypto.enc(f"gho_token_{gid}"))
    return gid


def client_for(gid, epoch=None, mode="contributor"):
    c = TestClient(main.app)
    epoch = db.get_user(gid)["session_epoch"] if epoch is None else epoch
    c.cookies.set("session", cookie({"uid": gid, "mode": mode, "epoch": epoch}))
    return c


# ---------- session invalidation ----------
def test_valid_session_works():
    gid = new_user()
    assert client_for(gid).get("/api/me").status_code == 200


def test_cookie_without_epoch_is_rejected():
    gid = new_user()
    c = TestClient(main.app)
    c.cookies.set("session", cookie({"uid": gid, "mode": "contributor"}))
    assert c.get("/api/me").status_code == 401


def test_logout_kills_copies_of_the_old_cookie():
    gid = new_user()
    stolen = client_for(gid)           # attacker holds a copy of the cookie
    victim = client_for(gid)
    assert victim.post("/api/logout", headers=H).status_code == 200
    assert stolen.get("/api/me").status_code == 401


def test_admin_cookie_is_dead_after_logout():
    gid = new_user("admin")
    stolen = client_for(gid)
    assert stolen.get("/api/admin/users").status_code == 200
    client_for(gid).post("/api/logout", headers=H)
    assert stolen.get("/api/admin/users").status_code == 401
    assert stolen.get("/api/admin/audit").status_code == 401


def test_stale_cookie_cannot_log_out_the_current_session():
    gid = new_user()
    old = client_for(gid, epoch=0)
    client_for(gid).post("/api/logout", headers=H)          # epoch -> 1
    fresh_epoch = db.get_user(gid)["session_epoch"]
    old.post("/api/logout", headers=H)                       # stale: must be a no-op
    assert db.get_user(gid)["session_epoch"] == fresh_epoch


def test_init_migrates_database_without_session_epoch(tmp_path, monkeypatch):
    old = sqlite3.connect(tmp_path / "app.db")
    old.execute("CREATE TABLE users (github_id INTEGER PRIMARY KEY, login TEXT NOT NULL, "
                "role TEXT NOT NULL DEFAULT 'contributor', added_by TEXT, last_login TEXT, gh_token TEXT)")
    old.execute("INSERT INTO users(github_id, login, role) VALUES (7, 'legacy', 'admin')")
    old.commit(); old.close()
    monkeypatch.setattr(db, "HOME", tmp_path)
    db.init()
    u = db.get_user(7)
    assert u["login"] == "legacy" and u["session_epoch"] == 0
    db.init()  # idempotent


# ---------- atomic job limits ----------
def test_active_cap_holds_under_concurrency():
    gid = new_user()
    barrier = threading.Barrier(12)

    def attempt(_):
        barrier.wait()  # fire all requests at the same instant
        return db.create_job_limited(gid, "solve", "{}", max_per_hour=100, max_active=2)[0]

    with ThreadPoolExecutor(12) as pool:
        created = [j for j in pool.map(attempt, range(12)) if j]
    assert len(created) == 2


def test_hourly_cap_and_reasons():
    gid = new_user()
    for _ in range(3):
        assert db.create_job_limited(gid, "solve", "{}", 3, 100)[0]
    assert db.create_job_limited(gid, "solve", "{}", 3, 100) == (None, "hourly")
    other = new_user()
    assert db.create_job_limited(other, "solve", "{}", 100, 0) == (None, "active")


def test_finished_jobs_free_up_active_slots():
    gid = new_user()
    jid, _ = db.create_job_limited(gid, "solve", "{}", 100, 1)
    assert db.create_job_limited(gid, "solve", "{}", 100, 1) == (None, "active")
    db.set_job(jid, "done", result="x")
    assert db.create_job_limited(gid, "solve", "{}", 100, 1)[0]


def test_api_returns_429_when_active_cap_reached(monkeypatch):
    gid = new_user()
    kid = db.add_key(gid, "k", "openrouter", "openai", "https://openrouter.ai/api/v1", "m", crypto.enc("sk-x" * 5))
    monkeypatch.setattr(main, "MAX_ACTIVE_JOBS", 0)
    r = client_for(gid).post("/api/jobs", headers=H, json={
        "kind": "solve", "repo": "octo/repo", "number": 1, "key_id": kid, "consent": True})
    assert r.status_code == 429 and "running jobs" in r.json()["detail"]


# ---------- retention ----------
def _age(table, col, row_id, days, id_col="id"):
    with db.conn() as c:
        c.execute(f"UPDATE {table} SET {col}=datetime('now', ?) WHERE {id_col}=?", (f"-{days} days", row_id))


def test_purge_removes_only_old_finished_jobs():
    gid = new_user()
    old_done, _ = db.create_job_limited(gid, "solve", "{}", 100, 100)
    old_running, _ = db.create_job_limited(gid, "solve", "{}", 100, 100)
    recent, _ = db.create_job_limited(gid, "solve", "{}", 100, 100)
    db.set_job(old_done, "done", result="secret model output")
    db.set_job(old_running, "running")
    db.set_job(recent, "done", result="fresh")
    for jid in (old_done, old_running):
        _age("jobs", "updated_at", jid, 45)
    db.purge_old(job_days=30, audit_days=0)
    assert db.get_job(old_done) is None
    assert db.get_job(old_running) is not None      # in-flight work is never purged
    assert db.get_job(recent) is not None


def test_purge_audit_and_zero_means_keep_forever():
    db.audit(None, "test.old")
    with db.conn() as c:
        c.execute("UPDATE audit SET ts=datetime('now','-400 days') WHERE action='test.old'")
    db.purge_old(job_days=0, audit_days=0)
    with db.conn() as c:
        assert c.execute("SELECT COUNT(*) FROM audit WHERE action='test.old'").fetchone()[0] == 1
    db.purge_old(job_days=0, audit_days=180)
    with db.conn() as c:
        assert c.execute("SELECT COUNT(*) FROM audit WHERE action='test.old'").fetchone()[0] == 0


def test_maybe_purge_is_rate_limited(monkeypatch):
    calls = []
    monkeypatch.setattr(db, "purge_old", lambda j, a: calls.append((j, a)))
    monkeypatch.setattr(db, "_last_purge", float("-inf"))
    db.maybe_purge(30, 180)
    db.maybe_purge(30, 180)
    assert calls == [(30, 180)]


# ---------- GitHub token revocation ----------
def _capture(monkeypatch):
    calls = []
    monkeypatch.setenv("GITHUB_CLIENT_ID", "cid")
    monkeypatch.setenv("GITHUB_CLIENT_SECRET", "csecret")
    monkeypatch.setattr(auth.httpx, "request", lambda method, url, **kw: calls.append((method, url, kw)))
    return calls


def test_logout_revokes_token_at_github(monkeypatch):
    calls = _capture(monkeypatch)
    gid = new_user()
    client_for(gid).post("/api/logout", headers=H)
    method, url, kw = calls[0]
    assert method == "DELETE" and url == "https://api.github.com/applications/cid/token"
    assert kw["json"] == {"access_token": f"gho_token_{gid}"} and kw["auth"] == ("cid", "csecret")
    assert db.get_user(gid)["gh_token"] is None


def test_removing_a_user_revokes_their_token(monkeypatch):
    calls = _capture(monkeypatch)
    admin, target = new_user("admin"), new_user()
    r = client_for(admin).delete(f"/api/admin/users/{target}", headers=H)
    assert r.status_code == 200 and db.get_user(target) is None
    assert calls and calls[0][2]["json"] == {"access_token": f"gho_token_{target}"}


def test_revocation_is_skipped_without_oauth_config_and_never_blocks_logout(monkeypatch):
    monkeypatch.delenv("GITHUB_CLIENT_ID", raising=False)
    monkeypatch.delenv("GITHUB_CLIENT_SECRET", raising=False)
    gid = new_user()
    assert client_for(gid).post("/api/logout", headers=H).status_code == 200
    # configured but GitHub unreachable: logout must still succeed
    monkeypatch.setenv("GITHUB_CLIENT_ID", "cid"); monkeypatch.setenv("GITHUB_CLIENT_SECRET", "s")
    def boom(*a, **k): raise OSError("network down")
    monkeypatch.setattr(auth.httpx, "request", boom)
    gid2 = new_user()
    assert client_for(gid2).post("/api/logout", headers=H).status_code == 200
    assert db.get_user(gid2)["gh_token"] is None


# ---------- shared HTTP client ----------
def test_shared_client_is_reused_and_recreated_after_close():
    a = github_client._shared()
    assert a is github_client._shared()
    github_client.close_client()
    b = github_client._shared()
    assert b is not a and not b.is_closed


def test_github_instances_share_one_pool_but_not_tokens():
    g1, g2 = github_client.GitHub("tok-1"), github_client.GitHub("tok-2")
    assert g1.http._headers["Authorization"] == "Bearer tok-1"
    assert g2.http._headers["Authorization"] == "Bearer tok-2"
    assert "Authorization" not in github_client.GitHub().http._headers


def test_shared_client_never_mixes_tokens_across_threads():
    """Sharing one connection pool is only safe if each request carries its own user's token."""
    import httpx
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append((self.path, self.headers.get("Authorization")))
            body = b'{"login": "x"}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    github_client.close_client()
    github_client._client = httpx.Client(base_url=f"http://127.0.0.1:{server.server_port}")
    try:
        def call(i):
            token = f"tok-{i % 2}"
            github_client.GitHub(token).http.get(f"/u/{i}")
            return i, token

        with ThreadPoolExecutor(16) as pool:
            expected = dict(pool.map(call, range(80)))
        assert len(seen) == 80
        for path, header in seen:
            assert header == f"Bearer {expected[int(path.rsplit('/', 1)[1])]}"
    finally:
        server.shutdown()
        github_client.close_client()
