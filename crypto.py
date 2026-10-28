"""Fernet encryption for secrets at rest (user API keys, GitHub tokens)."""
import os
from functools import lru_cache
from pathlib import Path
from cryptography.fernet import Fernet


@lru_cache
def _fernet() -> Fernet:
    env = os.environ.get("ISSUE_SOLVER_MASTER_KEY")  # preferred in production
    if env:
        return Fernet(env.encode())
    home = Path(os.environ.get("ISSUE_SOLVER_HOME", Path.home() / ".issue_solver"))
    home.mkdir(parents=True, exist_ok=True)
    p = home / "master.key"
    if not p.exists():
        p.write_bytes(Fernet.generate_key())
        p.chmod(0o600)
    return Fernet(p.read_bytes())


def enc(s: str) -> str:
    return _fernet().encrypt(s.encode()).decode()


def dec(s: str) -> str:
    return _fernet().decrypt(s.encode()).decode()


def mask(key: str) -> str:
    return key[:4] + "…" + key[-4:] if len(key) > 10 else "****"
