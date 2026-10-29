"""Emergency fix: make the GitHub account that was just refused an admin.

Run from the project folder:   python make_admin.py
"""
import os
import sqlite3

here = os.path.dirname(os.path.abspath(__file__))


def env_value(name):
    path = os.path.join(here, ".env")
    if os.path.exists(path):
        for line in open(path):
            if line.startswith(name + "="):
                return line.split("=", 1)[1].strip()
    return None


candidates = []
home = env_value("ISSUE_SOLVER_HOME")
if home:
    candidates.append(os.path.join(here, home, "app.db"))
candidates += [os.path.join(here, "data", "app.db"), os.path.expanduser("~/.issue_solver/app.db")]
dbs = []
for p in candidates:
    p = os.path.normpath(p)
    if os.path.exists(p) and p not in dbs:
        dbs.append(p)

print("Admin username in .env :", env_value("ADMIN_GITHUB_USERNAME") or "NOT SET")
if not dbs:
    print("No database found yet. Start the app, click 'Sign in with GitHub' once, then run this again.")
    raise SystemExit

best = None
for p in dbs:
    db = sqlite3.connect(p)
    users = db.execute("select login, role from users").fetchall()
    print(f"\nDatabase: {p}\n  allowed users now: {users or 'nobody'}")
    row = db.execute("select ts, target, detail from audit where action='login.denied' "
                     "order by ts desc, id desc limit 1").fetchone()
    if row and (best is None or row[0] > best[0][0]):
        best = (row, p)

if not best:
    print("\nNo refused sign-in found. Click 'Sign in with GitHub' once in the browser, then run this again.")
    raise SystemExit

(ts, gid, login), path = best
db = sqlite3.connect(path)
db.execute("insert into users(github_id, login, role, added_by) values (?,?,'admin','manual-fix') "
           "on conflict(github_id) do update set role='admin', login=excluded.login", (int(gid), login))
db.commit()
print(f"\nDONE: '{login}' is now an admin. Go back to the browser and sign in again.")
