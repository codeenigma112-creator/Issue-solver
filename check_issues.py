"""Find out why 'Load issues' is empty.   Run from the project folder:   python check_issues.py

Uses the GitHub login the app already saved for each signed-in user, asks GitHub two different
ways what is assigned to them, and explains the result. It never prints any token.
"""
import os
import sqlite3
import sys

here = os.path.dirname(os.path.abspath(__file__))
os.chdir(here)
sys.path.insert(0, here)

# load .env BEFORE importing the app's own modules (they read these at import time)
if os.path.exists(".env"):
    for line in open(".env").read().replace("\r", "").split("\n"):
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            os.environ[k.strip()] = v.strip().strip('"').strip("'")

import httpx  # noqa: E402
import crypto  # noqa: E402

API = os.environ.get("GITHUB_API_BASE", "https://api.github.com")
home = os.environ.get("ISSUE_SOLVER_HOME") or "./data"
dbfile = os.path.normpath(os.path.join(here, home, "app.db"))
if not os.path.exists(dbfile):
    print("No database yet. Start the app and sign in once, then run this again.")
    raise SystemExit
rows = sqlite3.connect(dbfile).execute("select login, gh_token from users where gh_token is not null").fetchall()
if not rows:
    print("Nobody has a saved GitHub login. Sign in to the app in the browser first, then run this again.")
    raise SystemExit


def ask(token, path, **params):
    return httpx.get(API + path, params=params, timeout=20, headers={
        "Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
        "User-Agent": "issue-solver-check", "X-GitHub-Api-Version": "2022-11-28"})


def label(i):
    repo = i.get("repository", {}).get("full_name") or i.get("repository_url", "").split("repos/")[-1]
    return f"{repo}#{i['number']}  {i['title'][:60]}"


for login, enc in rows:
    print("=" * 64)
    print("Account:", login)
    try:
        token = crypto.dec(enc)
    except Exception:
        print("  Could not unlock this account's saved login (secret key changed). Sign out and in again.")
        continue

    a = ask(token, "/issues", filter="assigned", state="open", per_page=100)
    if a.status_code != 200:
        print(f"  GitHub refused the main lookup: HTTP {a.status_code} {a.text[:120]}")
        print("  Sign out of the app and sign in again, then re-run this check.")
        continue
    scopes = a.headers.get("x-oauth-scopes", "(none)") or "(none)"
    items = a.json()
    real = [i for i in items if "pull_request" not in i]
    prs = len(items) - len(real)
    b = ask(token, "/search/issues", q=f"assignee:{login} is:issue is:open archived:false", per_page=100)
    found = b.json().get("total_count", 0) if b.status_code == 200 else None

    print("  Permissions the app was given :", scopes)
    print(f"  Narrow lookup (/issues)       : {len(real)} open issue(s)" + (f" (+{prs} pull request(s), skipped)" if prs else ""))
    for i in real[:8]:
        print("      ", label(i))
    print("  Wider lookup (search, in app) :", f"{found} open issue(s)" if found is not None else f"failed (HTTP {b.status_code})")
    if found:
        for i in b.json()["items"][:8]:
            print("      ", label(i))

    print("\n  VERDICT:")
    if found is None:
        print("  GitHub search, the lookup the app uses, failed. If this persists, sign out and")
        print("  sign in again to refresh the token.")
    elif found:
        print("  GitHub search finds your assigned issues, and that is the lookup the app uses.")
        print("  If the page still shows 'Nothing here', reload it and click Load issues again;")
        print("  if it's still empty, tell me.")
    else:
        print("  Neither lookup sees an open issue assigned to this account. Check these in order:")
        print("   1. Open https://github.com/issues/assigned while signed in as", login + ".")
        print("      If it's empty too, the issues are assigned to a different account or are closed.")
        print("   2. If they ARE listed there and are in PRIVATE repos: the app only has public access")
        print("      (see 'Permissions' above). Set GITHUB_OAUTH_SCOPE=\"repo read:user\" in .env, restart,")
        print("      sign out and sign in again, and approve the extra access.")
        print("   3. If they're in an ORGANIZATION: open https://github.com/settings/applications,")
        print("      click the app, and under 'Organization access' grant or request access for that org.")
        if prs:
            print(f"   4. {prs} of the items GitHub returned were pull requests, which the app skips.")
