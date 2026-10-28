"""GitHub API wrapper (always called with the *user's own* OAuth token)."""
import re
import httpx

LOGIN_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def valid_repo(repo: str) -> bool:
    if not REPO_RE.match(repo):
        return False
    owner, name = repo.split("/", 1)
    return owner not in (".", "..") and name not in (".", "..")


class GitHub:
    def __init__(self, token: str | None = None):
        h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if token:
            h["Authorization"] = f"Bearer {token}"
        self.http = httpx.Client(base_url="https://api.github.com", headers=h, timeout=30,
                                 follow_redirects=False)

    def _get(self, path, **params):
        r = self.http.get(path, params=params)
        r.raise_for_status()
        return r.json()

    def _paged(self, path, max_pages=10, **params):
        out, page = [], 1
        while page <= max_pages:
            batch = self._get(path, per_page=100, page=page, **params)
            if not batch:
                break
            out.extend(batch)
            if len(batch) < 100:
                break
            page += 1
        return out

    def user_by_login(self, login: str):
        if not LOGIN_RE.match(login):
            return None
        r = self.http.get(f"/users/{login}")
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return r.json()

    def assigned_issues(self) -> list[dict]:
        return [self._issue(i, i["repository"]["full_name"])
                for i in self._paged("/issues", filter="assigned", state="open")
                if "pull_request" not in i]

    def maintained_repos(self) -> list[dict]:
        repos = self._paged("/user/repos", affiliation="owner,collaborator,organization_member", sort="pushed")
        return [{"full_name": r["full_name"], "private": r["private"], "open_issues": r["open_issues_count"]}
                for r in repos
                if any(r.get("permissions", {}).get(k) for k in ("admin", "maintain", "push"))]

    def has_push(self, repo: str) -> bool:
        p = self._get(f"/repos/{repo}").get("permissions", {})
        return any(p.get(k) for k in ("admin", "maintain", "push"))

    def unassigned_issues(self, repo: str) -> list[dict]:
        items = self._get(f"/repos/{repo}/issues", state="open", assignee="none", per_page=100)
        return [self._issue(i, repo) for i in items if "pull_request" not in i]

    def get_issue(self, repo: str, number: int) -> dict:
        i = self._get(f"/repos/{repo}/issues/{int(number)}")
        if "pull_request" in i:
            raise ValueError("That number is a pull request, not an issue")
        out = self._issue(i, repo)
        out["body"] = i.get("body") or ""
        out["assignees"] = [a["login"] for a in i.get("assignees", [])]
        out["state"] = i.get("state")
        return out

    def issue_comments(self, repo: str, number: int, limit: int = 10) -> list[dict]:
        items = self._get(f"/repos/{repo}/issues/{int(number)}/comments", per_page=limit)
        return [{"author": c.get("user", {}).get("login", ""), "body": c.get("body") or ""} for c in items]

    def repo_labels(self, repo: str) -> list[str]:
        return [l["name"] for l in self._paged(f"/repos/{repo}/labels", max_pages=5)]

    def add_labels(self, repo: str, number: int, labels: list[str]) -> list[str]:
        r = self.http.post(f"/repos/{repo}/issues/{int(number)}/labels", json={"labels": labels})
        r.raise_for_status()
        return [l["name"] for l in r.json()]

    @staticmethod
    def _issue(i, repo):
        return {"repo": repo, "number": i["number"], "title": i["title"], "url": i["html_url"],
                "labels": [l["name"] for l in i["labels"]]}
