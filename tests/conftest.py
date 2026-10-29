import os
import tempfile

os.environ["ISSUE_SOLVER_HOME"] = tempfile.mkdtemp(prefix="issue-solver-test-")
os.environ["SESSION_SECRET"] = "test-session-secret"
os.environ.pop("ADMIN_GITHUB_USERNAME", None)
os.environ.pop("ALLOW_PRIVATE_BASE_URLS", None)

from cryptography.fernet import Fernet

os.environ["ISSUE_SOLVER_MASTER_KEY"] = Fernet.generate_key().decode()
os.environ["SOLVE_CI_WAIT"] = "0"
os.environ["SOLVE_CI_FIX_ATTEMPTS"] = "0"
