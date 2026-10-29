"""Thin chat client for OpenAI-compatible endpoints and Anthropic."""
import os
import time

import httpx

import providers
from providers import headers

_RETRY_STATUS = {429, 500, 502, 503, 504}


def _error_message(r: httpx.Response) -> str:
    if r.status_code == 429:
        return ("The model provider is rate limiting requests (429). Wait a minute or use a "
                "different key or model.")
    if 500 <= r.status_code < 600:
        return (f"The model provider is temporarily unavailable ({r.status_code}). The app retried "
                "automatically; try again shortly or choose a different model or key.")
    if r.status_code in (401, 403):
        return f"The model provider rejected the API key ({r.status_code}). Check the key and model access."
    if r.status_code == 404:
        return "The model or endpoint was not found (404). Check the model name and base URL."
    if r.status_code == 400:
        return "The model provider rejected the request (400). Check the model name and request limits."
    return f"The model provider returned HTTP {r.status_code}."


def _post(url: str, h: dict, body: dict, timeout: float) -> httpx.Response:
    retries = max(0, int(os.environ.get("LLM_RETRIES", "2")))
    delay = max(0.0, float(os.environ.get("LLM_RETRY_DELAY", "2")))
    for attempt in range(retries + 1):
        try:
            r = httpx.post(url, headers=h, json=body, timeout=timeout, follow_redirects=False)
        except httpx.HTTPError as exc:
            if attempt < retries:
                time.sleep(min(delay * (2 ** attempt), 30))
                continue
            raise RuntimeError(f"Could not reach the model provider: {exc}") from exc
        if r.status_code in _RETRY_STATUS and attempt < retries:
            wait = delay * (2 ** attempt)
            try:
                wait = max(wait, float(r.headers.get("retry-after", "")))
            except ValueError:
                pass
            time.sleep(min(wait, 30))
            continue
        if r.status_code >= 400:
            raise RuntimeError(_error_message(r))
        return r
    raise RuntimeError("The model provider did not return a response")


def _json(r: httpx.Response) -> dict:
    try:
        data = r.json()
    except ValueError as exc:
        raise RuntimeError("Model endpoint returned invalid JSON") from exc
    if not isinstance(data, dict):
        raise RuntimeError("Model endpoint returned an unexpected response")
    return data


def complete(entry: dict, messages: list[dict], max_tokens: int | None = None,
             cap: int | None = None) -> str:
    cap = int(cap or os.environ.get("LLM_MAX_TOKENS", "1200"))
    max_tokens = min(max_tokens or cap, cap)
    timeout = float(os.environ.get("LLM_TIMEOUT", "120"))
    base = entry["base_url"].rstrip("/")
    providers.assert_public_https(base)
    h = headers(entry["kind"], entry["api_key"])
    if entry["kind"] == "anthropic":
        system = "\n".join(m["content"] for m in messages if m["role"] == "system")
        body = {"model": entry["model"], "max_tokens": max_tokens,
                "messages": [m for m in messages if m["role"] != "system"]}
        if system:
            body["system"] = system
        data = _json(_post(f"{base}/messages", h, body, timeout))
        return "".join(b.get("text", "") for b in data.get("content", [])).strip()
    body = {"model": entry["model"], "messages": messages, "max_tokens": max_tokens}
    data = _json(_post(f"{base}/chat/completions", h, body, timeout))
    try:
        return (data["choices"][0]["message"]["content"] or "").strip()
    except (KeyError, IndexError, TypeError):
        raise RuntimeError("Model endpoint returned an unexpected response")
