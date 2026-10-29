"""Check and repair the .env settings file, then start Issue Solver.

Run from the project folder:   python fix_and_start.py
(If the app is already running, press Ctrl+C in its terminal first.)
"""
import os
import secrets
import shutil
import socket
import sqlite3
import subprocess
import sys

from cryptography.fernet import Fernet

here = os.path.dirname(os.path.abspath(__file__))
os.chdir(here)
ENV = os.path.join(here, ".env")


def ok(msg): print("  [ok]    " + msg)
def fixed(msg): print("  [fixed] " + msg)
def bad(msg): print("  [PROBLEM] " + msg)


def parse(lines):
    out = {}
    for line in lines:
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip('"').strip("'").strip()
    return out


def valid_fernet(k):
    try:
        Fernet(k.encode())
        return True
    except Exception:
        return False


def set_line(lines, key, value):
    for i, line in enumerate(lines):
        if line.split("=", 1)[0].strip() == key:
            lines[i] = f"{key}={value}"
            return
    lines.append(f"{key}={value}")


# --- the app must not already be running on port 8000
s = socket.socket()
try:
    s.bind(("0.0.0.0", 8000))
except OSError:
    print("The app is already running (port 8000 is busy).")
    print("Click in the terminal where it is running, press Ctrl+C, then run this again.")
    raise SystemExit(1)
finally:
    s.close()

print("\nChecking your settings file (.env)")
if not os.path.exists(ENV):
    print("  No .env file found. Run:  bash setup_codespace.sh")
    raise SystemExit(1)

lines = open(ENV).read().replace("\r", "").split("\n")
cfg = parse(lines)
changed = False
regenerated_key = False

# master key
mk = cfg.get("ISSUE_SOLVER_MASTER_KEY", "")
if valid_fernet(mk):
    ok("secret master key is valid")
elif mk and valid_fernet(mk + "="):
    set_line(lines, "ISSUE_SOLVER_MASTER_KEY", mk + "=")
    fixed("master key had lost its final '=' sign; put it back (nothing else needed)")
    changed = True
else:
    shutil.copy(ENV, ENV + ".bak")
    set_line(lines, "ISSUE_SOLVER_MASTER_KEY", Fernet.generate_key().decode())
    fixed(f"master key was unusable (length {len(mk)}); made a new one. Old file saved as .env.bak")
    changed = regenerated_key = True

# session secret
if not cfg.get("SESSION_SECRET"):
    set_line(lines, "SESSION_SECRET", secrets.token_urlsafe(32))
    fixed("session secret was missing; made one")
    changed = True
else:
    ok("session secret is set")

# things only you can supply: report, don't invent
missing = []
for name in ("GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET", "ADMIN_GITHUB_USERNAME", "BASE_URL"):
    v = cfg.get(name, "")
    if not v:
        bad(f"{name} is empty. Run:  bash setup_codespace.sh")
        missing.append(name)
    elif name == "GITHUB_CLIENT_ID":
        ok(f"{name} is set ({len(v)} characters)")
    elif name == "GITHUB_CLIENT_SECRET":
        ok(f"{name} is set ({len(v)} characters)")
    else:
        ok(f"{name} = {v}")
cid, sec = cfg.get("GITHUB_CLIENT_ID", ""), cfg.get("GITHUB_CLIENT_SECRET", "")
if sec and len(sec) != 40:
    bad("GITHUB_CLIENT_SECRET is not 40 characters (GitHub's are 40). Copy it again from your OAuth app.")
if cid and (" " in cid or len(cid) < 15):
    bad("GITHUB_CLIENT_ID looks too short; GitHub's are about 20 characters.")

if changed:
    open(ENV, "w").write("\n".join(lines).rstrip("\n") + "\n")
    os.chmod(ENV, 0o600)
    cfg = parse(lines)

# if a brand-new key was made, anything saved with the old key is unreadable: clear it
if regenerated_key:
    home = cfg.get("ISSUE_SOLVER_HOME") or "./data"
    dbfile = os.path.normpath(os.path.join(here, home, "app.db"))
    if os.path.exists(dbfile):
        db = sqlite3.connect(dbfile)
        n_keys = db.execute("delete from keys").rowcount
        n_tok = db.execute("update users set gh_token=NULL where gh_token is not NULL").rowcount
        db.commit()
        if n_keys or n_tok:
            fixed(f"cleared {n_keys} saved model key(s) and {n_tok} login token(s) that the old key can't open; "
                  "sign in again and re-add your model key")

if missing:
    print("\nNot starting: the settings above marked PROBLEM must be filled in first.")
    print("Run:  bash setup_codespace.sh   (it asks for them), then run this again if needed.")
    raise SystemExit(1)

# tests: show only what failed
print("\nRunning the tests (shows only failures)")
try:
    r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-rf", "--no-header", "-p", "no:cacheprovider"],
                       capture_output=True, text=True, timeout=180)
    out = r.stdout.splitlines()
    fails = [l for l in out if l.startswith("FAILED")]
    for l in fails:
        print("  " + l[:230])
    print("  " + (out[-1] if out else "no test output"))
except Exception as e:
    print("  (could not run tests:", e, ")")

# start the app with the repaired settings
print("\nStarting the app. Open:", cfg.get("BASE_URL", "(see BASE_URL in .env)"))
print("Stop it any time with Ctrl+C.\n")
env = dict(os.environ)
env.update(cfg)
os.execvpe(sys.executable, [sys.executable, "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"], env)
