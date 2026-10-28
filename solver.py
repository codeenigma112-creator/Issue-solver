"""Server-side job runner: solve issues, triage labels, and draft replies."""
import json
import logging
import os
from concurrent.futures import ThreadPoolExecutor

import crypto, db, llm
from github_client import GitHub, valid_repo

log = logging.getLogger("issue_solver.solver")

KINDS = ("solve", "triage", "reply")
MAX_INPUT_CHARS = int(os.environ.get("MAX_ISSUE_CHARS", "20000"))

_executor = ThreadPoolExecutor(max_workers=int(os.environ.get("SOLVER_WORKERS", "2")),
                               thread_name_prefix="solver")


def submit(job_id: str) -> None:
    _executor.submit(_run_safe, job_id)


def shutdown() -> None:
    _executor.shutdown(wait=False, cancel_futures=True)


def _run_safe(job_id: str) -> None:
    job = db.get_job(job_id)
    if not job or job["status"] != "queued":
        return
    user = db.get_user(job["user_id"])
    db.set_job(job_id, "running")
    db.audit(user, "job.start", target=job_id, detail=job["kind"])
    try:
        result = _dispatch(job, user)
        db.set_job(job_id, "done", result=result)
        db.audit(user, "job.done", target=job_id, detail=job["kind"])
    except Exception as exc:
        log.exception("job %s failed", job_id)
        db.set_job(job_id, "error", error=str(exc)[:500])
        db.audit(user, "job.error", target=job_id, detail=str(exc)[:500])


def _dispatch(job: dict, user: dict | None) -> str:
    if not user:
        raise RuntimeError("User no longer exists")
    data = json.loads(job["input"])
    repo = data.get("repo", "")
    number = data.get("number")
    if not valid_repo(repo) or not isinstance(number, int) or number <= 0:
        raise RuntimeError("Invalid issue reference")
    if not user.get("gh_token"):
        raise RuntimeError("Sign in again to run jobs")
    key = db.get_key(user["github_id"], data.get("key_id", ""))
    if not key:
        raise RuntimeError("That model key no longer exists")
    entry = dict(key)
    entry["api_key"] = crypto.dec(key["api_key"])
    gh = GitHub(crypto.dec(user["gh_token"]))
    kind = job["kind"]
    instructions = str(data.get("instructions") or "")[:2000]
    if kind == "solve":
        return _solve(gh, user, repo, number, entry, instructions)
    if kind in ("triage", "reply"):
        if user["role"] not in ("maintainer", "admin"):
            raise RuntimeError("Maintainer access required")
        if kind == "triage":
            return _triage(gh, repo, number, entry, instructions)
        return _reply(gh, repo, number, entry, instructions)
    raise RuntimeError("Unknown job kind")


def _solve(gh: GitHub, user: dict, repo: str, number: int, entry: dict, instructions: str) -> str:
    issue = gh.get_issue(repo, number)
    if user["login"] not in issue["assignees"] and not gh.has_push(repo):
        raise RuntimeError("You are not assigned to this issue")
    body = issue["body"][:MAX_INPUT_CHARS]
    prompt = (f"Repository: {repo}\nIssue #{number}: {issue['title']}\n"
              f"Labels: {', '.join(issue['labels']) or 'none'}\n\n{body}")
    if instructions:
        prompt += f"\n\nAdditional instructions:\n{instructions}"
    messages = [
        {"role": "system", "content": (
            "You are a senior software engineer helping a contributor with a GitHub issue. "
            "Return a concrete implementation plan and, when useful, a unified diff. "
            "Do not claim to have run code or tests. Be concise and specific.")},
        {"role": "user", "content": prompt},
    ]
    return llm.complete(entry, messages)


def _triage(gh: GitHub, repo: str, number: int, entry: dict, instructions: str) -> str:
    if not gh.has_push(repo):
        raise RuntimeError("Write access to that repo is required")
    issue = gh.get_issue(repo, number)
    labels = gh.repo_labels(repo)
    if not labels:
        raise RuntimeError("This repository has no labels to choose from")
    body = issue["body"][:MAX_INPUT_CHARS]
    prompt = (f"Repository: {repo}\nIssue #{number}: {issue['title']}\n"
              f"Current labels: {', '.join(issue['labels']) or 'none'}\n"
              f"Available labels: {json.dumps(labels)}\n\n{body}")
    if instructions:
        prompt += f"\n\nAdditional instructions:\n{instructions}"
    messages = [
        {"role": "system", "content": (
            "You triage GitHub issues. Choose at most 5 labels ONLY from the available labels list. "
            "Return strict JSON with keys 'labels' (array of strings) and 'rationale' (short string).")},
        {"role": "user", "content": prompt},
    ]
    raw = llm.complete(entry, messages)
    return json.dumps(_parse_triage(raw, labels))


def _reply(gh: GitHub, repo: str, number: int, entry: dict, instructions: str) -> str:
    if not gh.has_push(repo):
        raise RuntimeError("Write access to that repo is required")
    issue = gh.get_issue(repo, number)
    comments = gh.issue_comments(repo, number)
    body = issue["body"][:MAX_INPUT_CHARS]
    thread = "\n\n".join(f"{c['author']}: {c['body'][:2000]}" for c in comments)
    prompt = (f"Repository: {repo}\nIssue #{number}: {issue['title']}\n\n{body}")
    if thread:
        prompt += f"\n\nRecent comments:\n{thread}"
    if instructions:
        prompt += f"\n\nAdditional instructions:\n{instructions}"
    messages = [
        {"role": "system", "content": (
            "You draft a professional, friendly reply to a GitHub issue. "
            "Do not promise work you cannot do. Return only the reply text, with no preamble.")},
        {"role": "user", "content": prompt},
    ]
    return llm.complete(entry, messages)


def _parse_triage(raw: str, available: list[str]) -> dict:
    text = raw.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
    start, end = text.find("{"), text.rfind("}")
    data = None
    if start >= 0 and end > start:
        try:
            data = json.loads(text[start:end + 1])
        except ValueError:
            data = None
    allowed = set(available)
    picked, rationale = [], ""
    if isinstance(data, dict):
        rationale = str(data.get("rationale") or "")[:2000]
        raw_labels = data.get("labels") or []
        if isinstance(raw_labels, list):
            picked = [str(x) for x in raw_labels if str(x) in allowed]
    else:
        rationale = text[:2000]
    return {"labels": list(dict.fromkeys(picked))[:5], "rationale": rationale}
