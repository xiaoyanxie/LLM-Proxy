#!/usr/bin/env bash

# Usage: ./run.sh <port> <ca_cert_path> <ca_key_path>
# Example: ./run.sh 9540 proxyCrts/proxy_ca.crt proxyCrts/proxy_ca.key

set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "Usage: $0 <port> <ca_cert_path> <ca_key_path>"
  exit 1
fi

PORT="$1"
CA_CERT="$2"
CA_KEY="$3"

if [[ ! -f "$CA_CERT" ]]; then
  echo "Missing cert file: $CA_CERT"
  exit 1
fi
if [[ ! -f "$CA_KEY" ]]; then
  echo "Missing key file: $CA_KEY"
  exit 1
fi

# Load env vars from .env (if present)
if [[ -f .env ]]; then
  set -a
  . ./.env
  set +a
fi

echo "Using llm_server_apiKey=${llm_server_apiKey:-<not set>}"
echo "Using llm_server_endPoint=${llm_server_endPoint:-<not set>}"
echo "Starting with proxy args: PORT=$PORT, CERT=$CA_CERT, KEY=$CA_KEY"

# Prefer Python 3.12 because Flask 2.2.x does not run on Python 3.14.
PYTHON_BIN="python3"
if command -v python3.12 >/dev/null 2>&1; then
  PYTHON_BIN="python3.12"
fi

echo "Using Python interpreter: $PYTHON_BIN"
TARGET_PY_VER="$($PYTHON_BIN -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"

# Rebuild venv if it does not match the selected interpreter version.
if [[ -x .venv/bin/python ]]; then
  VENV_PY_VER="$(.venv/bin/python -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
  if [[ "$VENV_PY_VER" != "$TARGET_PY_VER" ]]; then
    echo "Recreating .venv (current=$VENV_PY_VER, target=$TARGET_PY_VER)"
    rm -rf .venv
  fi
fi

# Create/update local virtual environment
if [[ ! -d .venv ]]; then
  "$PYTHON_BIN" -m venv .venv
fi
. .venv/bin/activate
python -m pip install --upgrade pip >/dev/null
python -m pip install -r src/llm-server/requirements.txt >/dev/null

# Build frontend widget assets consumed by Python injection app
npm install >/dev/null
npm run build

# Build your personal root-level C proxy implementation
make clean
make

python src/llm-server/app.py >/tmp/cs112_llm_server.log 2>&1 &
PY_PID=$!

# Wait until Python app is healthy before starting proxy
READY=0
for _ in $(seq 1 20); do
  if curl -fsS http://127.0.0.1:8080/health >/dev/null 2>&1; then
    READY=1
    break
  fi
  sleep 0.5
done

if [[ "$READY" -ne 1 ]]; then
  echo "Python server did not become healthy. See /tmp/cs112_llm_server.log"
  kill "$PY_PID" >/dev/null 2>&1 || true
  exit 1
fi

./proxy "$PORT" "$CA_CERT" "$CA_KEY" &
C_PID=$!

echo "Python server PID: $PY_PID"
echo "C proxy PID: $C_PID"
echo "Servers running. Press Ctrl-C to stop both."

cleanup() {
  echo "Stopping..."
  kill "$PY_PID" "$C_PID" >/dev/null 2>&1 || true
}
trap cleanup INT TERM

wait
