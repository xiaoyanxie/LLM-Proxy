#!/bin/bash

# Usage: ./run.sh <port> <ca_cert_path> <ca_key_path>
# Example: ./run.sh 9540 proxyCrts/proxy_ca.crt proxyCrts/proxy_ca.key

set -e

if [ "$#" -ne 3 ]; then
  echo "Usage: $0 <port> <ca_cert_path> <ca_key_path>"
  exit 1
fi

PORT="$1"
CA_CERT="$2"
CA_KEY="$3"

# Load env vars from .env (if present)
if [ -f .env ]; then
  set -a
  . .env
  set +a
fi

echo "Using llm_server_apiKey=${llm_server_apiKey:-<not set>}"
echo "Starting with proxy args: PORT=$PORT, CERT=$CA_CERT, KEY=$CA_KEY"

# Build frontend
npm run build

# Build C proxy
cd src/https_proxy
make clean
make
cp proxy ../../proxy
cd ../..

# Start Python server
python3 src/llm-server/app.py &
PY_PID=$!

# Start C proxy with passed arguments
./proxy "$PORT" "$CA_CERT" "$CA_KEY" &
C_PID=$!

echo "Python server PID: $PY_PID"
echo "C server PID: $C_PID"
echo "Servers running. Press Ctrl-C to stop both."

# Stop both servers on Ctrl-C
trap "echo 'Stopping...'; kill $PY_PID $C_PID 2>/dev/null" INT TERM

# Wait so script doesn't exit immediately
wait