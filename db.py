"""SQLite storage: allowlisted users (by GitHub ID) and their encrypted model keys."""
import os, sqlite3, uuid
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
  gh_token TEXT
);
CREATE TABLE IF NOT EXISTS keys (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(github_id) ON DELETE CASCADE,
  label TEXT, provider TEXT, kind TEXT, base_url TEXT, model TEXT,
  api_key TEXT NOT NULL
);
"""


@contextmanager
def conn():
    HOME.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(HOME / "app.db")
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    try:
        yield c
        c.commit()
    finally:
        c.close()


def init():
    with conn() as c:
        c.executescript(SCHEMA)


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


def add_key(user_id, label, provider, kind, base_url, model, enc_key):
    kid = uuid.uuid4().hex[:8]
    with conn() as c:
        c.execute("INSERT INTO keys VALUES (?,?,?,?,?,?,?,?)",
                  (kid, user_id, label, provider, kind, base_url, model, enc_key))
    return kid


def list_keys(user_id):
    with conn() as c:
        return [dict(r) for r in c.execute("SELECT * FROM keys WHERE user_id=?", (user_id,))]


def delete_key(user_id, key_id):
    with conn() as c:
        return c.execute("DELETE FROM keys WHERE id=? AND user_id=?", (key_id, user_id)).rowcount > 0
