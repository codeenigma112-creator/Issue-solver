"""Thin chat client for OpenAI-compatible endpoints and Anthropic."""
import os
import httpx
import providers
from providers import headers


def complete(entry: dict, messages: list[dict], max_tokens: int | None = None) -> str:
    cap = int(os.environ.get("LLM_MAX_TOKENS", "1200"))
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
        r = httpx.post(f"{base}/messages", headers=h, json=body, timeout=timeout, follow_redirects=False)
        r.raise_for_status()
        data = r.json()
        return "".join(b.get("text", "") for b in data.get("content", [])).strip()
    r = httpx.post(f"{base}/chat/completions", headers=h, timeout=timeout, follow_redirects=False,
                   json={"model": entry["model"], "messages": messages, "max_tokens": max_tokens})
    r.raise_for_status()
    data = r.json()
    try:
        return (data["choices"][0]["message"]["content"] or "").strip()
    except (KeyError, IndexError, TypeError):
        raise RuntimeError("Model endpoint returned an unexpected response")
