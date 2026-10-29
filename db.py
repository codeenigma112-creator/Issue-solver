"""SQLite storage: allowlisted users (by GitHub ID), encrypted model keys, jobs, and audit log."""
import os, sqlite3, time, uuid
from contextlib import contextmanager
from pathlib import Path

HOME = Path(os.environ.get("ISSUE_SOLVER_HOME", Path.home() / ".issue_solver"))
ROLES = ("contributor", "maintainer", "admin")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  github_id INTEGER PRIMARY KEY,
  login TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'contributor' CHECK (role IN ('contributor','maintainer','admin')),
  added_by TEXT,
  last_login TEXT,
  gh_token TEXT,
  session_epoch INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS keys (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(github_id) ON DELETE CASCADE,
  label TEXT, provider TEXT, kind TEXT, base_url TEXT, model TEXT,
  api_key TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS jobs (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(github_id) ON DELETE CASCADE,
  kind TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued',
  input TEXT NOT NULL,
  result TEXT,
  error TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_jobs_user ON jobs(user_id, created_at DESC);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL DEFAULT (datetime('now')),
  actor_id INTEGER,
  actor_login TEXT,
  action TEXT NOT NULL,
  target TEXT,
  detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts DESC);
"""


@contextmanager
def conn():
    HOME.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(HOME / "app.db")
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    c.execute("PRAGMA busy_timeout=5000")
    try:
        yield c
        c.commit()
    finally:
        c.close()


def init():
    with conn() as c:
        c.execute("PRAGMA journal_mode=WAL")
        c.executescript(SCHEMA)
        # Migrate databases created before session_epoch existed.
        cols = {r["name"] for r in c.execute("PRAGMA table_info(users)")}
        if "session_epoch" not in cols:
            c.execute("ALTER TABLE users ADD COLUMN session_epoch INTEGER NOT NULL DEFAULT 0")
    try:
        os.chmod(HOME, 0o700)
        os.chmod(HOME / "app.db", 0o600)
    except OSError:
        pass


def get_user(github_id):
    with conn() as c:
        r = c.execute("SELECT * FROM users WHERE github_id=?", (github_id,)).fetchone()
    return dict(r) if r else None


def list_users():
    with conn() as c:
        rows = c.execute("SELECT github_id, login, role, added_by, last_login FROM users ORDER BY login").fetchall()
    return [dict(r) for r in rows]


def add_user(github_id, login, role, added_by):
    """Raises sqlite3.IntegrityError if already present."""
    with conn() as c:
        c.execute("INSERT INTO users(github_id, login, role, added_by) VALUES (?,?,?,?)",
                  (github_id, login, role, added_by))


def set_role(github_id, role):
    with conn() as c:
        c.execute("UPDATE users SET role=? WHERE github_id=?", (role, github_id))


def remove_user(github_id):
    with conn() as c:
        c.execute("DELETE FROM users WHERE github_id=?", (github_id,))


def count_admins():
    with conn() as c:
        return c.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0]


def record_login(github_id, login, enc_token):
    with conn() as c:
        c.execute("UPDATE users SET login=?, gh_token=?, last_login=datetime('now') WHERE github_id=?",
                  (login, enc_token, github_id))


def clear_token(github_id):
    with conn() as c:
        c.execute("UPDATE users SET gh_token=NULL WHERE github_id=?", (github_id,))


def bump_session_epoch(github_id):
    """Invalidate every signed session cookie issued for this user."""
    with conn() as c:
        c.execute("UPDATE users SET session_epoch=session_epoch+1 WHERE github_id=?", (github_id,))


def add_key(user_id, label, provider, kind, base_url, model, enc_key):
    kid = uuid.uuid4().hex[:8]
    with conn() as c:
        c.execute("INSERT INTO keys VALUES (?,?,?,?,?,?,?,?)",
                  (kid, user_id, label, provider, kind, base_url, model, enc_key))
    return kid


def list_keys(user_id):
    with conn() as c:
        return [dict(r) for r in c.execute("SELECT * FROM keys WHERE user_id=?", (user_id,))]


def get_key(user_id, key_id):
    with conn() as c:
        r = c.execute("SELECT * FROM keys WHERE id=? AND user_id=?", (key_id, user_id)).fetchone()
    return dict(r) if r else None


def delete_key(user_id, key_id):
    with conn() as c:
        return c.execute("DELETE FROM keys WHERE id=? AND user_id=?", (key_id, user_id)).rowcount > 0


def create_job(user_id, kind, input_json):
    jid = uuid.uuid4().hex
    with conn() as c:
        c.execute("INSERT INTO jobs(id, user_id, kind, input) VALUES (?,?,?,?)",
                  (jid, user_id, kind, input_json))
    return jid


def create_job_limited(user_id, kind, input_json, max_per_hour, max_active):
    """Check the per-user limits and insert the job in ONE write transaction.

    BEGIN IMMEDIATE takes SQLite's write lock before counting, so two simultaneous requests
    can't both see "room for one more". Returns (job_id, None) or (None, "hourly" | "active").
    """
    jid = uuid.uuid4().hex
    with conn() as c:
        c.execute("BEGIN IMMEDIATE")
        recent = c.execute("SELECT COUNT(*) FROM jobs WHERE user_id=? AND created_at >= datetime('now', '-3600 seconds')",
                           (user_id,)).fetchone()[0]
        if recent >= max_per_hour:
            return None, "hourly"
        active = c.execute("SELECT COUNT(*) FROM jobs WHERE user_id=? AND status IN ('queued','running')",
                           (user_id,)).fetchone()[0]
        if active >= max_active:
            return None, "active"
        c.execute("INSERT INTO jobs(id, user_id, kind, input) VALUES (?,?,?,?)",
                  (jid, user_id, kind, input_json))
    return jid, None


def set_job(job_id, status, result=None, error=None):
    with conn() as c:
        c.execute("UPDATE jobs SET status=?, result=COALESCE(?, result), error=?, updated_at=datetime('now') WHERE id=?",
                  (status, result, error, job_id))


def get_job(job_id, user_id=None):
    with conn() as c:
        if user_id is None:
            r = c.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        else:
            r = c.execute("SELECT * FROM jobs WHERE id=? AND user_id=?", (job_id, user_id)).fetchone()
    return dict(r) if r else None


def list_jobs(user_id, limit=20):
    with conn() as c:
        rows = c.execute("SELECT id, kind, status, result, error, created_at, updated_at FROM jobs "
                         "WHERE user_id=? ORDER BY created_at DESC LIMIT ?", (user_id, limit)).fetchall()
    return [dict(r) for r in rows]


def count_jobs_since(user_id, seconds):
    with conn() as c:
        return c.execute("SELECT COUNT(*) FROM jobs WHERE user_id=? "
                         "AND created_at >= datetime('now', ?)", (user_id, f"-{int(seconds)} seconds")).fetchone()[0]


def count_active_jobs(user_id):
    with conn() as c:
        return c.execute("SELECT COUNT(*) FROM jobs WHERE user_id=? AND status IN ('queued','running')",
                         (user_id,)).fetchone()[0]


def fail_stale_jobs():
    with conn() as c:
        c.execute("UPDATE jobs SET status='error', error='Interrupted by restart', updated_at=datetime('now') "
                  "WHERE status IN ('queued','running')")


_last_purge = float("-inf")


def purge_old(job_days: int, audit_days: int) -> tuple[int, int]:
    """Delete finished jobs and audit rows older than the given ages (0 = keep forever).
    Queued/running jobs are never touched."""
    jobs = logs = 0
    with conn() as c:
        if job_days > 0:
            jobs = c.execute("DELETE FROM jobs WHERE status NOT IN ('queued','running') "
                             "AND updated_at < datetime('now', ?)", (f"-{int(job_days)} days",)).rowcount
        if audit_days > 0:
            logs = c.execute("DELETE FROM audit WHERE ts < datetime('now', ?)",
                             (f"-{int(audit_days)} days",)).rowcount
    return jobs, logs


def maybe_purge(job_days: int, audit_days: int, every_seconds: int = 3600) -> None:
    """Cheap, rate-limited purge so long-running servers clean up without a scheduler."""
    global _last_purge
    now = time.monotonic()
    if now - _last_purge < every_seconds:
        return
    _last_purge = now
    purge_old(job_days, audit_days)


def audit(actor, action, target=None, detail=None):
    actor_id = actor.get("github_id") if actor else None
    actor_login = actor.get("login") if actor else None
    with conn() as c:
        c.execute("INSERT INTO audit(actor_id, actor_login, action, target, detail) VALUES (?,?,?,?,?)",
                  (actor_id, actor_login, action, target, detail))


def list_audit(limit=200):
    with conn() as c:
        rows = c.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]
