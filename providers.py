"""Provider presets, live key validation, and SSRF guard for custom base URLs."""
import ipaddress, os, socket
from urllib.parse import urlparse
import httpx

PRESETS = {
    "openrouter": {"kind": "openai", "base_url": "https://openrouter.ai/api/v1", "hint": "e.g. google/gemini-2.5-flash"},
    "openai": {"kind": "openai", "base_url": "https://api.openai.com/v1", "hint": "e.g. gpt-4o"},
    "gemini": {"kind": "openai", "base_url": "https://generativelanguage.googleapis.com/v1beta/openai", "hint": "e.g. gemini-2.5-flash"},
    "anthropic": {"kind": "anthropic", "base_url": "https://api.anthropic.com/v1", "hint": "e.g. claude-sonnet-4-5"},
    "custom": {"kind": "openai", "base_url": "", "hint": "any OpenAI-compatible endpoint"},
}


def headers(kind: str, api_key: str) -> dict:
    if kind == "anthropic":
        return {"x-api-key": api_key, "anthropic-version": "2023-06-01"}
    return {"Authorization": f"Bearer {api_key}"}


def assert_public_https(url: str) -> None:
    """Users can supply a base URL the SERVER will call -> block internal targets (SSRF)."""
    p = urlparse(url)
    if p.scheme != "https" or not p.hostname:
        raise ValueError("Base URL must start with https://")
    if p.username or p.password:
        raise ValueError("Base URL must not contain credentials")
    if os.environ.get("ALLOW_PRIVATE_BASE_URLS") == "1":  # e.g. self-hosted local models
        return
    try:
        port = p.port or 443
        infos = socket.getaddrinfo(p.hostname, port)
    except (socket.gaierror, ValueError):
        raise ValueError("Base URL host could not be resolved")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                or ip.is_multicast or ip.is_unspecified):
            raise ValueError("Base URL must point to a public host")


def validate_key(kind: str, base_url: str, api_key: str) -> tuple[bool, str]:
    try:
        r = httpx.get(f"{base_url.rstrip('/')}/models", headers=headers(kind, api_key),
                      timeout=15, follow_redirects=False)
    except httpx.HTTPError as e:
        return False, f"network error: {e}"
    if r.status_code == 200:
        return True, "key accepted"
    if r.status_code in (401, 403):
        return False, "provider rejected the key"
    if r.status_code in (404, 405):
        return True, "endpoint does not expose /models; key stored unverified"
    return False, f"unexpected status {r.status_code}"
