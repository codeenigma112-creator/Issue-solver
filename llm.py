"""Thin chat client for OpenAI-compatible endpoints and Anthropic."""
import httpx
from providers import headers


def complete(entry: dict, messages: list[dict], max_tokens: int = 1024) -> str:
    base = entry["base_url"].rstrip("/")
    h = headers(entry["kind"], entry["api_key"])
    if entry["kind"] == "anthropic":
        system = "\n".join(m["content"] for m in messages if m["role"] == "system")
        body = {"model": entry["model"], "max_tokens": max_tokens,
                "messages": [m for m in messages if m["role"] != "system"]}
        if system:
            body["system"] = system
        r = httpx.post(f"{base}/messages", headers=h, json=body, timeout=120)
        r.raise_for_status()
        return "".join(b.get("text", "") for b in r.json()["content"])
    r = httpx.post(f"{base}/chat/completions", headers=h, timeout=120,
                   json={"model": entry["model"], "messages": messages, "max_tokens": max_tokens})
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"]
