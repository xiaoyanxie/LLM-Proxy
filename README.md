# LLM-Proxy

[![Language C](https://img.shields.io/badge/language-C-00599C?logo=c&logoColor=white)](#)
[![Frontend Vite](https://img.shields.io/badge/frontend-vite-646CFF?logo=vite&logoColor=white)](#)
[![Backend Flask](https://img.shields.io/badge/backend-flask-black?logo=flask)](#)

HTTPS interception proxy with LLM-assisted HTML injection.

## Architecture
- `proxy.c` + `Makefile`: C-based HTTPS proxy (socket handling, TLS MITM flow, forwarding).
- `src/llm-server/app.py`: Flask service for response processing, injection, and LLM endpoints.
- `src/widget/*`: front-end widget source bundled to `web_static/widget.js` and `web_static/widget.css`.

## Runtime Flow
1. Browser traffic is forwarded to the C proxy.
2. Target responses are passed to the Flask service (`/inject-resp`).
3. HTML is modified to include the widget snippet.
4. Widget requests summaries or related output from the LLM endpoint.

## Quick Start
1. Create environment config:
```bash
cp .env.example .env
```
2. Fill `.env`:
```dotenv
llm_server_endPoint=<LLM API endpoint>
llm_server_apiKey=<LLM API key>
```
3. Prepare CA cert/key files (example below) or reuse existing files.
4. Start all services:
```bash
./run.sh 9540 proxyCrts/proxy_ca.crt proxyCrts/proxy_ca.key
```

## Local CA Generation (Optional)
```bash
mkdir -p proxyCrts
openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
  -keyout proxyCrts/proxy_ca.key \
  -out proxyCrts/proxy_ca.crt \
  -subj "/CN=LLM Proxy CA"
```

## API Endpoints
- `GET /health`: service health check.
- `POST /inject-resp`: receives full HTTP response bytes and returns injected output.

## Compatibility Notes
- Python 3.12 is recommended.
