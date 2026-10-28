"""GitHub API wrapper (always called with the *user's own* OAuth token)."""
import re
import httpx

LOGIN_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
REPO_RE = re.compile(r"^[\w.-]+/[\w.-]+$")


class GitHub:
    def __init__(self, token: str | None = None):
        h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if token:
            h["Authorization"] = f"Bearer {token}"
        self.http = httpx.Client(base_url="https://api.github.com", headers=h, timeout=30)

    def _get(self, path, **params):
        r = self.http.get(path, params=params)
        r.raise_for_status()
        return r.json()

    def user_by_login(self, login: str):
        if not LOGIN_RE.match(login):
            return None
        r = self.http.get(f"/users/{login}")
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return r.json()

    def assigned_issues(self) -> list[dict]:
        me = self._get("/user")["login"]
        out, page = [], 1
        while True:
            batch = self._get("/issues", filter="assigned", state="open", per_page=100, page=page)
            if not batch:
                break
            for i in batch:
                repo = i["repository"]
                if "pull_request" not in i and (repo["owner"]["login"] == me or repo["fork"]):
                    out.append(self._issue(i, repo["full_name"]))
            page += 1
        return out

    def maintained_repos(self) -> list[dict]:
        repos = self._get("/user/repos", affiliation="owner,collaborator,organization_member",
                          sort="pushed", per_page=100)
        return [{"full_name": r["full_name"], "private": r["private"], "open_issues": r["open_issues_count"]}
                for r in repos
                if any(r.get("permissions", {}).get(k) for k in ("admin", "maintain", "push"))]

    def has_push(self, repo: str) -> bool:
        p = self._get(f"/repos/{repo}").get("permissions", {})
        return any(p.get(k) for k in ("admin", "maintain", "push"))

    def unassigned_issues(self, repo: str) -> list[dict]:
        items = self._get(f"/repos/{repo}/issues", state="open", assignee="none", per_page=50)
        return [self._issue(i, repo) for i in items if "pull_request" not in i]

    @staticmethod
    def _issue(i, repo):
        return {"repo": repo, "number": i["number"], "title": i["title"], "url": i["html_url"],
                "labels": [l["name"] for l in i["labels"]]}
