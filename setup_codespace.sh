#!/usr/bin/env bash
# One-time setup + start for running Issue Solver inside a GitHub Codespace.
# Safe to re-run: it keeps your existing secrets so stored model keys stay readable.
set -e
cd "$(dirname "$0")"

if [ -z "$CODESPACE_NAME" ]; then
  echo "This script is meant to be run inside a GitHub Codespace."; exit 1
fi
PY=$(command -v python || command -v python3)
BASE_URL="https://${CODESPACE_NAME}-8000.${GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN:-app.github.dev}"

echo
echo "=== STEP 1 of 3: your GitHub OAuth app ==="
echo "Open https://github.com/settings/developers  ->  OAuth Apps  ->  New OAuth App"
echo "(if you already made one, just edit it so these two values match):"
echo
echo "  Homepage URL:               $BASE_URL"
echo "  Authorization callback URL: $BASE_URL/auth/callback"
echo
echo "Then click 'Register application' and 'Generate a new client secret'."
echo
read -rp "Press Enter when you have the Client ID and Client Secret... " _

echo
echo "=== STEP 2 of 3: settings ==="
read -rp "Your GitHub username (you become the admin): " ADMIN
ADMIN=$(echo "$ADMIN" | tr -d '[:space:]@')
read -rp "Client ID: " CID
CID=$(echo "$CID" | tr -d '[:space:]')
read -rsp "Client Secret (hidden as you type): " CSECRET; echo
CSECRET=$(echo "$CSECRET" | tr -d '[:space:]')
if [ -z "$ADMIN" ] || [ -z "$CID" ] || [ -z "$CSECRET" ]; then
  echo "Username, Client ID and Client Secret are all required. Run the script again."; exit 1
fi

echo "Installing what the app needs (about a minute the first time)..."
pip install -q -r requirements.txt -r requirements-dev.txt

# Reuse existing secrets if there are any: a NEW master key would make saved model keys unreadable.
old() { [ -f .env ] && grep -E "^$1=" .env | head -1 | cut -d= -f2- || true; }
MASTER_KEY=$(old ISSUE_SOLVER_MASTER_KEY)
SESSION_SECRET=$(old SESSION_SECRET)
[ -z "$MASTER_KEY" ] && [ -f data/master.key ] && MASTER_KEY=$(cat data/master.key)
[ -n "$MASTER_KEY" ] || MASTER_KEY=$($PY -c "from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())")
[ -n "$SESSION_SECRET" ] || SESSION_SECRET=$($PY -c "import secrets;print(secrets.token_urlsafe(32))")

cat > .env <<ENV
GITHUB_CLIENT_ID=$CID
GITHUB_CLIENT_SECRET=$CSECRET
ADMIN_GITHUB_USERNAME=$ADMIN
SESSION_SECRET=$SESSION_SECRET
ISSUE_SOLVER_MASTER_KEY=$MASTER_KEY
BASE_URL=$BASE_URL
ISSUE_SOLVER_HOME=./data
ENV
chmod 600 .env
# Make sure secrets can never be committed by accident.
touch .gitignore
grep -qx ".env" .gitignore || echo ".env" >> .gitignore
grep -qx "data/" .gitignore || echo "data/" >> .gitignore

echo
echo "Running the safety tests..."
$PY -m pytest -q 2>&1 | tail -1

echo
echo "=== STEP 3 of 3: starting the app ==="
echo "Open this address in your browser:  $BASE_URL"
echo "(or click 'Open in Browser' when the popup appears, or use the PORTS tab). Stop the app with Ctrl+C."
echo
set -a; . ./.env; set +a
exec $PY -m uvicorn main:app --host 0.0.0.0 --port 8000
