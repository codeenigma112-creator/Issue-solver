import json
import random

import pytest
from fastapi.testclient import TestClient

import auth
import crypto
import db
import providers
import solver
from github_client import valid_repo
from main import app


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


def uid():
    return random.randint(10**9, 10**10)


def test_index_serves_html(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "Issue Solver" in r.text


def test_static_assets_are_mounted(client):
    r = client.get("/static/app.js")
    assert r.status_code == 200
    assert "startJob" in r.text


def test_security_headers(client):
    r = client.get("/")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["referrer-policy"] == "no-referrer"


def test_me_requires_login(client):
    assert client.get("/api/me").status_code == 401


def test_providers_requires_login(client):
    assert client.get("/api/providers").status_code == 401


def test_csrf_header_required(client):
    assert client.post("/api/logout").status_code == 403


def test_logout_with_csrf(client):
    assert client.post("/api/logout", headers={"X-CSRF": "1"}).status_code == 200


def test_unknown_path_is_404(client):
    assert client.get("/does-not-exist").status_code == 404


def test_crypto_roundtrip():
    secret = "sk-test-value-123456"
    assert crypto.dec(crypto.enc(secret)) == secret


def test_crypto_mask():
    assert crypto.mask("sk-abcdefghijklmnop").startswith("sk-a")
    assert crypto.mask("short") == "****"


def test_db_user_lifecycle():
    gid = uid()
    db.add_user(gid, "alice", "contributor", "tester")
    assert db.get_user(gid)["role"] == "contributor"
    db.set_role(gid, "maintainer")
    assert db.get_user(gid)["role"] == "maintainer"
    assert any(u["github_id"] == gid for u in db.list_users())
    db.remove_user(gid)
    assert db.get_user(gid) is None


def test_db_count_admins():
    gid = uid()
    before = db.count_admins()
    db.add_user(gid, "admin-x", "admin", "tester")
    assert db.count_admins() == before + 1
    db.remove_user(gid)
    assert db.count_admins() == before


def test_db_key_lifecycle():
    gid = uid()
    db.add_user(gid, "key-user", "contributor", "tester")
    kid = db.add_key(gid, "test", "openai", "openai", "https://api.openai.com/v1", "gpt-4o", "enc")
    assert db.get_key(gid, kid)["label"] == "test"
    assert len(db.list_keys(gid)) == 1
    assert db.delete_key(gid, kid) is True
    assert db.delete_key(gid, kid) is False
    db.remove_user(gid)


def test_db_token_clearing():
    gid = uid()
    db.add_user(gid, "token-user", "contributor", "tester")
    db.record_login(gid, "token-user", "encrypted")
    assert db.get_user(gid)["gh_token"] == "encrypted"
    db.clear_token(gid)
    assert db.get_user(gid)["gh_token"] is None
    db.remove_user(gid)


def test_db_audit_log():
    actor = {"github_id": uid(), "login": "auditor"}
    db.audit(actor, "test.action", target="x", detail="y")
    assert db.list_audit(1)[0]["action"] == "test.action"
    db.audit(None, "test.anonymous")


def test_db_job_lifecycle():
    gid = uid()
    db.add_user(gid, "job-user", "contributor", "tester")
    jid = db.create_job(gid, "solve", '{"repo":"a/b","number":1,"key_id":"k"}')
    assert db.get_job(jid, gid)["status"] == "queued"
    assert db.count_active_jobs(gid) == 1
    db.set_job(jid, "running")
    assert db.get_job(jid)["status"] == "running"
    db.set_job(jid, "done", result="ok")
    job = db.get_job(jid, gid)
    assert job["status"] == "done"
    assert job["result"] == "ok"
    assert db.count_active_jobs(gid) == 0
    assert db.count_jobs_since(gid, 3600) == 1
    assert db.list_jobs(gid)[0]["id"] == jid
    assert db.get_job(jid, uid()) is None
    db.remove_user(gid)


def test_db_fail_stale_jobs():
    gid = uid()
    db.add_user(gid, "stale-user", "contributor", "tester")
    jid = db.create_job(gid, "solve", "{}")
    db.set_job(jid, "running")
    db.fail_stale_jobs()
    assert db.get_job(jid)["status"] == "error"
    db.remove_user(gid)


def test_provider_presets():
    assert providers.PRESETS["openai"]["kind"] == "openai"
    assert providers.PRESETS["anthropic"]["kind"] == "anthropic"
    assert providers.PRESETS["custom"]["base_url"] == ""


def test_ssrf_rejects_http():
    with pytest.raises(ValueError):
        providers.assert_public_https("http://example.com")


def test_ssrf_rejects_private_ip():
    with pytest.raises(ValueError):
        providers.assert_public_https("https://127.0.0.1")


def test_ssrf_private_opt_out(monkeypatch):
    monkeypatch.setenv("ALLOW_PRIVATE_BASE_URLS", "1")
    providers.assert_public_https("https://127.0.0.1")


def test_valid_repo_accepts_normal_name():
    assert valid_repo("owner/repo") is True
    assert valid_repo("owner/repo.name") is True


def test_valid_repo_rejects_traversal():
    assert valid_repo("../etc") is False
    assert valid_repo("owner/..") is False


def test_valid_repo_rejects_missing_slash():
    assert valid_repo("owner") is False


def test_can_maintain_roles():
    assert auth.can_maintain({"role": "maintainer"}) is True
    assert auth.can_maintain({"role": "admin"}) is True
    assert auth.can_maintain({"role": "contributor"}) is False


def test_parse_triage_fenced_json():
    raw = '```json\n{"labels": ["bug", "nope"], "rationale": "looks broken"}\n```'
    out = solver._parse_triage(raw, ["bug", "feature"])
    assert out["labels"] == ["bug"]
    assert out["rationale"] == "looks broken"


def test_parse_triage_non_json():
    out = solver._parse_triage("I think this is a bug", ["bug"])
    assert out["labels"] == []
    assert "bug" in out["rationale"]


def test_solver_kinds():
    assert solver.KINDS == ("solve", "triage", "reply")


class FakeGitHub:
    def __init__(self, token):
        self.token = token

    def get_issue(self, repo, number):
        return {"repo": repo, "number": number, "title": "Crash on startup", "url": "https://github.com/a/b/issues/1",
                "labels": ["bug"], "body": "It crashes.", "assignees": ["solver-user"], "state": "open"}

    def has_push(self, repo):
        return True

    def repo_labels(self, repo):
        return ["bug", "feature"]

    def issue_comments(self, repo, number):
        return [{"author": "reporter", "body": "Any update?"}]


def make_job(kind, role="contributor", prompt="A plan"):
    gid = uid()
    login = "solver-user"
    db.add_user(gid, login, role, "tester")
    db.record_login(gid, login, crypto.enc("gh-token"))
    kid = db.add_key(gid, "test", "openai", "openai", "https://api.openai.com/v1", "gpt-4o",
                     crypto.enc("sk-test-123456"))
    payload = json.dumps({"repo": "a/b", "number": 1, "key_id": kid, "instructions": ""})
    jid = db.create_job(gid, kind, payload)
    return gid, jid


def fake_model(monkeypatch, output):
    monkeypatch.setattr(solver, "GitHub", FakeGitHub)
    monkeypatch.setattr(solver.llm, "complete", lambda entry, messages, max_tokens=None: output)


def test_job_solve_runs_server_side(monkeypatch):
    fake_model(monkeypatch, "Here is a plan.")
    gid, jid = make_job("solve")
    solver._run_safe(jid)
    job = db.get_job(jid)
    assert job["status"] == "done"
    assert job["result"] == "Here is a plan."
    db.remove_user(gid)


def test_job_triage_filters_unknown_labels(monkeypatch):
    fake_model(monkeypatch, '{"labels": ["bug", "nope"], "rationale": "crash"}')
    gid, jid = make_job("triage", role="maintainer")
    solver._run_safe(jid)
    job = db.get_job(jid)
    assert job["status"] == "done"
    assert json.loads(job["result"])["labels"] == ["bug"]
    db.remove_user(gid)


def test_job_triage_requires_maintainer(monkeypatch):
    fake_model(monkeypatch, '{"labels": ["bug"], "rationale": "crash"}')
    gid, jid = make_job("triage", role="contributor")
    solver._run_safe(jid)
    job = db.get_job(jid)
    assert job["status"] == "error"
    assert "Maintainer" in job["error"]
    db.remove_user(gid)


def test_job_reply_runs(monkeypatch):
    fake_model(monkeypatch, "Thanks for the report.")
    gid, jid = make_job("reply", role="admin")
    solver._run_safe(jid)
    job = db.get_job(jid)
    assert job["status"] == "done"
    assert job["result"] == "Thanks for the report."
    db.remove_user(gid)


def test_job_fails_without_github_token(monkeypatch):
    fake_model(monkeypatch, "unused")
    gid, jid = make_job("solve")
    db.clear_token(gid)
    solver._run_safe(jid)
    job = db.get_job(jid)
    assert job["status"] == "error"
    assert "Sign in again" in job["error"]
    db.remove_user(gid)


def test_ssrf_rejects_ipv4_mapped_loopback(monkeypatch):
    import socket
    monkeypatch.setattr(providers.socket, "getaddrinfo",
                        lambda *a, **k: [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::ffff:127.0.0.1", 443, 0, 0))])
    with pytest.raises(ValueError):
        providers.assert_public_https("https://example.com")


def test_ssrf_rejects_credentials():
    with pytest.raises(ValueError):
        providers.assert_public_https("https://user:pass@example.com")
