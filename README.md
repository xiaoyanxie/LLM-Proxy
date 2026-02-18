# CS112 HTTPS Proxy

[![Language C](https://img.shields.io/badge/language-C-00599C?logo=c&logoColor=white)](#)
[![Frontend Vite](https://img.shields.io/badge/frontend-vite-646CFF?logo=vite&logoColor=white)](#)
[![Backend Flask](https://img.shields.io/badge/backend-flask-black?logo=flask)](#)

Hybrid project with browser widget + Python injection server + C HTTPS proxy.

## What Runs Together
- Root `proxy.c` + `Makefile`: your personal C proxy implementation.
- `src/llm-server/app.py`: injection and LLM-related API layer.
- `src/widget/*`: browser widget bundled into `web_static/widget.js`.

## Quick Start
1. Prepare `.env` from `.env.example` (put your LLM endpoint and API key).
2. Ensure you have CA cert/key files (see example below).
3. Run:

```bash
./run.sh 9540 proxyCrts/proxy_ca.crt proxyCrts/proxy_ca.key
```

The script will:
- create/use `.venv` with Python dependencies,
- install Node dependencies,
- build widget assets,
- build your root C proxy,
- start Flask on `:8080`,
- start proxy on your chosen port.

## Generate Local CA (if needed)
```bash
mkdir -p proxyCrts
openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
  -keyout proxyCrts/proxy_ca.key \
  -out proxyCrts/proxy_ca.crt \
  -subj "/CN=CS112 Proxy CA"
```

## Notes
- Python 3.12 is recommended (Flask 2.2.x is incompatible with Python 3.14).
- This repo was rebuilt from a downloaded snapshot with a clean commit history.
