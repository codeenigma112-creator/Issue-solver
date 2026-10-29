"""GitHub API wrapper (always called with the *user's own* OAuth token)."""
import re
import threading
import httpx

LOGIN_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def valid_repo(repo: str) -> bool:
    if not REPO_RE.match(repo):
        return False
    owner, name = repo.split("/", 1)
    return owner not in (".", "..") and name not in (".", "..")


_client: httpx.Client | None = None
_client_lock = threading.Lock()


def _shared() -> httpx.Client:
    """One connection pool for the whole app (httpx.Client is thread-safe). Creating a Client
    per request, as before, leaked a socket pool every time and never closed it."""
    global _client
    with _client_lock:
        if _client is None or _client.is_closed:
            _client = httpx.Client(base_url="https://api.github.com", timeout=30, follow_redirects=False)
        return _client


def close_client() -> None:
    global _client
    with _client_lock:
        if _client is not None:
            _client.close()
            _client = None


class _Http:
    """Per-user view over the shared pool: same get/post API, user's token on each request."""

    def __init__(self, token: str | None):
        self._headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if token:
            self._headers["Authorization"] = f"Bearer {token}"

    def get(self, path, params=None):
        return _shared().get(path, params=params, headers=self._headers)

    def post(self, path, json=None):
        return _shared().post(path, json=json, headers=self._headers)

    def patch(self, path, json=None):
        return _shared().patch(path, json=json, headers=self._headers)


class GitHub:
    def __init__(self, token: str | None = None):
        self.http = _Http(token)

    def _get(self, path, **params):
        r = self.http.get(path, params=params)
        r.raise_for_status()
        return r.json()

    def _post(self, path, **body):
        r = self.http.post(path, json=body)
        r.raise_for_status()
        return r.json()

    def _patch(self, path, **body):
        r = self.http.patch(path, json=body)
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

    def _search(self, q: str) -> list[dict]:
        out, page = [], 1
        while page <= 10:
            batch = self._get("/search/issues", q=q, per_page=100, page=page)
            items = batch.get("items", [])
            out.extend(items)
            if len(items) < 100 or page * 100 >= batch.get("total_count", 0):
                break
            page += 1
        return out

    def assigned_issues(self) -> list[dict]:
        items = self._search("assignee:@me is:issue is:open archived:false")
        out = []
        for i in items:
            if "pull_request" in i:
                continue
            repo = self._repo_name(i)
            prs = self.linked_prs(repo, i["number"])
            out.append({**self._issue(i, repo), "has_pr": bool(prs), "linked_prs": prs})
        return out

    @staticmethod
    def _repo_name(i) -> str:
        repo = i.get("repository", {}).get("full_name")
        return repo or i.get("repository_url", "").split("/repos/")[-1]

    def issue_timeline(self, repo: str, number: int) -> list[dict]:
        headers = {**self.http._headers, "Accept": "application/vnd.github.mockingbird-preview+json"}
        r = _shared().get(f"/repos/{repo}/issues/{int(number)}/timeline", headers=headers,
                          params={"per_page": 100})
        if r.status_code == 404:
            return []
        r.raise_for_status()
        data = r.json()
        return data if isinstance(data, list) else []

    def linked_prs(self, repo: str, number: int) -> list[int]:
        out = []
        try:
            events = self.issue_timeline(repo, number)
        except Exception:
            return out
        for ev in events:
            if not isinstance(ev, dict):
                continue
            kind = ev.get("event")
            if kind not in ("cross-referenced", "connected", "referenced"):
                continue
            # cross-referenced: source.issue.pull_request
            source = ev.get("source")
            if isinstance(source, dict):
                issue = source.get("issue")
                if isinstance(issue, dict) and issue.get("pull_request"):
                    n = issue.get("number")
                    if isinstance(n, int) and n not in out:
                        out.append(n)
                    continue
            # connected: subject may be a PR
            subject = ev.get("subject")
            if isinstance(subject, dict) and subject.get("pull_request"):
                n = subject.get("number")
                if isinstance(n, int) and n not in out:
                    out.append(n)
            # some payloads include issue.number + pull_request at top of event
            if ev.get("pull_request") and isinstance(ev.get("issue"), dict):
                n = ev["issue"].get("number")
                if isinstance(n, int) and n not in out:
                    out.append(n)
        return out

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
        out = []
        for i in items:
            if "pull_request" in i:
                continue
            prs = self.linked_prs(repo, i["number"])
            out.append({**self._issue(i, repo), "has_pr": bool(prs), "linked_prs": prs})
        return out

    def get_issue(self, repo: str, number: int) -> dict:
        i = self._get(f"/repos/{repo}/issues/{int(number)}")
        if "pull_request" in i:
            raise ValueError("That number is a pull request, not an issue")
        out = self._issue(i, repo)
        out["body"] = i.get("body") or ""
        out["assignees"] = [a["login"] for a in i.get("assignees", [])]
        out["state"] = i.get("state")
        return out

    def repo_info(self, repo: str) -> dict:
        return self._get(f"/repos/{repo}")

    def branch_head(self, repo: str, branch: str) -> str:
        return self._get(f"/repos/{repo}/git/ref/heads/{branch}")["object"]["sha"]

    def commit(self, repo: str, sha: str) -> dict:
        return self._get(f"/repos/{repo}/git/commits/{sha}")

    def tree(self, repo: str, sha: str) -> dict:
        return self._get(f"/repos/{repo}/git/trees/{sha}", recursive=1)

    def blob(self, repo: str, sha: str) -> dict:
        return self._get(f"/repos/{repo}/git/blobs/{sha}")

    def create_blob(self, repo: str, content: str) -> str:
        return self._post(f"/repos/{repo}/git/blobs", content=content, encoding="utf-8")["sha"]

    def create_tree(self, repo: str, base_tree: str, entries: list[dict]) -> dict:
        return self._post(f"/repos/{repo}/git/trees", base_tree=base_tree, tree=entries)

    def create_commit(self, repo: str, message: str, tree: str, parents: list[str]) -> dict:
        return self._post(f"/repos/{repo}/git/commits", message=message, tree=tree, parents=parents)

    def create_branch(self, repo: str, branch: str, sha: str) -> dict:
        return self._post(f"/repos/{repo}/git/refs", ref=f"refs/heads/{branch}", sha=sha)

    def create_pull(self, repo: str, title: str, head: str, base: str, body: str) -> dict:
        return self._post(f"/repos/{repo}/pulls", title=title, head=head, base=base, body=body)

    def fork(self, repo: str) -> dict:
        return self._post(f"/repos/{repo}/forks")

    def merge_upstream(self, repo: str, branch: str) -> dict:
        return self._post(f"/repos/{repo}/merge-upstream", branch=branch)

    def update_ref(self, repo: str, branch: str, sha: str) -> dict:
        return self._patch(f"/repos/{repo}/git/refs/heads/{branch}", sha=sha, force=False)

    def check_runs(self, repo: str, ref: str) -> dict:
        return self._get(f"/repos/{repo}/commits/{ref}/check-runs")

    def commit_statuses(self, repo: str, ref: str) -> list[dict]:
        return self._get(f"/repos/{repo}/statuses/{ref}")

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
