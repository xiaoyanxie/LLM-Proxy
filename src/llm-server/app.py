from flask import Flask, request, jsonify, Response, send_from_directory
from bs4 import BeautifulSoup
from flask_cors import CORS
from llmproxy import generate

import threading
import uuid
import gzip
import zlib
import os
import asyncio
from typing import Dict, Any, List, Optional
import time
import re
import hashlib

try:
    import brotli
except Exception:
    brotli = None

# -------------------------------------------------------------------
# Paths / app
# -------------------------------------------------------------------

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
STATIC_DIR = os.path.join(ROOT_DIR, "web_static")
ASSETS_DIR = os.path.join(ROOT_DIR, "static_assets")
os.makedirs(STATIC_DIR, exist_ok=True)

app = Flask(__name__)
CORS(app)

# page_id -> raw HTML
PAGE_STORE: Dict[str, str] = {}
PAGE_STORE_LOCK = threading.Lock()

# page_id -> cached witty comment string
COMMENT_CACHE: Dict[str, str] = {}
COMMENT_LOCK = threading.Lock()

# page_id -> informative page record
LEARN_STORE: Dict[str, Dict[str, Any]] = {}
LEARN_LOCK = threading.Lock()

# Current session’s active reading time per page_id
ACTIVE_TIME: Dict[str, float] = {}
ACTIVE_TIME_LOCK = threading.Lock()

# Global “session running” flag
SESSION_RUNNING: bool = False
SESSION_STARTED_AT: Optional[float] = None
SESSION_LOCK = threading.Lock()

MIN_READ_SECONDS = 10.0 

avatar_pos = {"left": 120.0, "bottom": 80.0}

def split_http_response(raw: bytes):
    """
    Splits raw HTTP response into (header_bytes, body_bytes).
    Handles both CRLF and LF.
    """
    sep = b"\r\n\r\n"
    idx = raw.find(sep)
    if idx == -1:
        sep = b"\n\n"
        idx = raw.find(sep)
        if idx == -1:
            return raw, b""

    header = raw[:idx + len(sep)]
    body = raw[idx + len(sep):]
    return header, body


def parse_headers(header_bytes: bytes):
    """
    Parses HTTP headers into a dict.

    header_bytes: b"HTTP/1.1 200 OK\\r\\nContent-Type: text/html\\r\\n..."
    returns: (first_line, {lower_name: value, ...})
    """
    header_text = header_bytes.decode("utf-8", errors="ignore")
    lines = header_text.split("\r\n")
    first_line = lines[0] if lines else ""
    headers = {}

    for line in lines[1:]:
        if ":" in line:
            name, val = line.split(":", 1)
            headers[name.strip().lower()] = val.strip()

    return first_line, headers


def inject_before_body_end(html: str, snippet: str) -> str:
    """
    Minimal, markup-preserving injection: drop the snippet before the last </body>
    if present; otherwise before </html>; otherwise append at the end.
    """
    lower = html.lower()
    body_idx = lower.rfind("</body>")
    if body_idx != -1:
        return html[:body_idx] + snippet + html[body_idx:]
    html_idx = lower.rfind("</html>")
    if html_idx != -1:
        return html[:html_idx] + snippet + html[html_idx:]
    return html + snippet


def looks_like_html(doc: str) -> bool:
    """
    Heuristic: only inject when we're confident this is the actual HTML document.
    """
    if not doc:
        return False
    sample = doc[:2000].lower()
    return (
        "<html" in sample
        or "<!doctype html" in sample
        or "<body" in sample
        or "<head" in sample
    )


def dechunk_body(data: bytes) -> bytes:
    """
    Minimal dechunker for HTTP/1.1 chunked transfer encoding.
    Returns the dechunked body or raises on failure.
    """
    out = bytearray()
    i = 0
    n = len(data)
    while True:
        j = data.find(b"\r\n", i)
        if j == -1:
            raise ValueError("incomplete chunk size line")
        line = data[i:j]
        try:
            chunk_size = int(line.split(b";", 1)[0], 16)
        except Exception as e:
            raise ValueError(f"bad chunk size: {e}")
        i = j + 2
        if chunk_size == 0:
            if i + 1 < n and data[i:i+2] == b"\r\n":
                i += 2
            break
        if i + chunk_size > n:
            raise ValueError("incomplete chunk data")
        out.extend(data[i:i+chunk_size])
        i += chunk_size
        if i + 1 >= n or data[i:i+2] != b"\r\n":
            raise ValueError("missing chunk CRLF")
        i += 2
    return bytes(out)

def truncate_text(text: str, max_chars: int = 4000) -> str:
    """
    Trim text to at most max_chars to keep LLM latency down.
    Keep paragraph boundaries if possible.
    """
    if len(text) <= max_chars:
        return text
    out: List[str] = []
    total = 0
    for para in text.split("\n"):
        if not para:
            continue
        if total + len(para) + 1 > max_chars:
            break
        out.append(para)
        total += len(para) + 1
    if not out:
        return text[:max_chars]
    return "\n".join(out)


def extract_readable_text(html: str) -> str:
    soup = BeautifulSoup(html, "lxml")

    # Remove non-content elements
    for tag in soup(["script", "style", "noscript", "nav", "header", "footer", "form", "iframe"]):
        tag.decompose()

    text = soup.get_text(separator=" ", strip=True)
    text = re.sub(r"\s+", " ", text)

    return text


def extract_title(html: str) -> str:
    soup = BeautifulSoup(html, "lxml")

    if soup.title and soup.title.string:
        return soup.title.string.strip()
    h1 = soup.find("h1")
    if h1:
        return h1.get_text(strip=True)

    return ""


STOPWORDS = {
    "this", "that", "with", "from", "such", "have", "will", "your", "their", "about",
    "there", "which", "also", "into", "over", "these", "those", "them", "they",
    "when", "what", "were", "been", "after", "before", "because", "would",
    "could", "should", "then", "than", "only", "very", "more", "most", "some",
    "many", "other", "just", "like", "used", "using", "use",
    "its", "it's", "the", "and", "for", "you", "are", "but", "not", "can", "all",
    "was", "our", "has", "may", "too"
}


def extract_keywords(body: str, max_keywords: int = 10) -> List[str]:
    words = re.findall(r"[a-zA-Z]{4,}", body.lower())

    freq: Dict[str, int] = {}
    for w in words:
        if w in STOPWORDS:
            continue
        freq[w] = freq.get(w, 0) + 1

    keywords = sorted(freq, key=freq.get, reverse=True)[:max_keywords]
    return keywords

def store_page(page_id: str, html: str) -> None:
    if not page_id or html is None:
        return
    with PAGE_STORE_LOCK:
        PAGE_STORE[page_id] = html


def get_page(page_id: str) -> Optional[str]:
    if not page_id:
        return None
    with PAGE_STORE_LOCK:
        return PAGE_STORE.get(page_id)


def should_treat_as_informative(url: str, html: str) -> bool:
    lower = url.lower()
    blocked_substrings = [
        "doubleclick", "adservice", "/ads", "/advert",
        "/oauth", "/login", "/signin", "/auth", "/sso"
    ]
    if any(b in lower for b in blocked_substrings):
        return False

    text = extract_readable_text(html)
    if len(text) < 200:
        return False

    return True


def append_learn_page(page_id: str, url: str, html: str) -> None:
    if not html:
        return

    if not should_treat_as_informative(url or "", html):
        return

    text = extract_readable_text(html)
    if len(text) < 400:
        return

    title = extract_title(html)
    snippet = truncate_text(text, 2000)

    record = {
        "page_id": page_id,
        "url": url or "",
        "title": title or "",
        "snippet": snippet,
        "ts_first_seen": time.time(),
    }

    with LEARN_LOCK:
        if page_id not in LEARN_STORE:
            LEARN_STORE[page_id] = record


def get_learn_history() -> List[Dict[str, Any]]:
    with LEARN_LOCK:
        return list(LEARN_STORE.values())


def get_learn_record_for_page(page_id: str) -> Optional[Dict[str, Any]]:
    if not page_id:
        return None
    with LEARN_LOCK:
        return LEARN_STORE.get(page_id)

# -------------------------------------------------------------------
# Active time per page (global single session)
# -------------------------------------------------------------------

def add_active_time(page_id: str, delta_seconds: float) -> None:
    if not page_id or delta_seconds <= 0.0:
        return
    with ACTIVE_TIME_LOCK:
        ACTIVE_TIME[page_id] = ACTIVE_TIME.get(page_id, 0.0) + float(delta_seconds)


def get_active_time() -> Dict[str, float]:
    with ACTIVE_TIME_LOCK:
        return dict(ACTIVE_TIME)


def start_session() -> None:
    global SESSION_RUNNING, SESSION_STARTED_AT
    with SESSION_LOCK:
        SESSION_RUNNING = True
        SESSION_STARTED_AT = time.time()
    with ACTIVE_TIME_LOCK:
        ACTIVE_TIME.clear()


def end_session() -> None:
    global SESSION_RUNNING, SESSION_STARTED_AT
    with SESSION_LOCK:
        SESSION_RUNNING = False
        SESSION_STARTED_AT = None
    with ACTIVE_TIME_LOCK:
        ACTIVE_TIME.clear()

def llm_comment(html: str) -> str:
    text = extract_readable_text(html)
    title = extract_title(html)
    print("llm comment for", title)
    body = text[:2000]
    keywords = extract_keywords(body)
    query = f"""
PAGE TITLE:
{title}

MAIN TEXT EXCERPT:
{body}

KEYWORDS:
{", ".join(keywords)}

TASK:
Give one witty insight about this page.
"""

    resp = generate(
        model="us.meta.llama3-2-1b-instruct-v1:0",
        system="""
You are a concise, playful companion who reacts to webpages the user is reading.

Your job is to produce ONE short, witty insight based on the page’s content.
Rules:
- Output exactly ONE or TWO sentence.
- Maximum length: 100 characters.
- Tone: lightly playful, clever, companion-like. Not flirty.
- No summaries, no explanations, no lists.
- Do not mention that you are an AI.
- The sentence must relate to the page’s topic based on the provided text.
- The sentence can potentially end with a question, serve as a conversation starter with user.

If the page content is extremely general (e.g. homepages, link hubs),
comment on the site's overall vibe instead of any specific detail.

Your entire reply should be ONLY that one sentence.
""",
        query=query,
        temperature=0.3,
        lastk=0,
        session_id="WikiSession",
        rag_usage=False,
    )
    print("end comment for ", title)
    return resp["response"]


def describe_time_span(seconds: float) -> str:
    if seconds <= 0:
        return "this moment"
    minutes = seconds / 60.0
    hours = seconds / 3600.0
    if minutes < 1.5:
        return "the last minute or so"
    if minutes < 60:
        return f"the last {int(round(minutes))} minutes"
    if hours < 3:
        return f"the last {hours:.1f} hours"
    if hours < 24:
        return f"the last {int(round(hours))} hours"
    days = hours / 24.0
    return f"the last {int(round(days))} days"


def build_learning_context(pages: List[Dict[str, Any]], max_chars: int = 8000) -> str:
    """
    Turn the informative pages (with active_seconds) into a text block.

    Each entry includes:
    [rank] (Xs) Title - URL
    snippet...
    """
    if not pages:
        return "No informative pages captured."

    # Sort by active_seconds desc, then by ts_first_seen asc
    pages_sorted = sorted(
        pages,
        key=lambda p: (-float(p.get("active_seconds", 0.0)), float(p.get("ts_first_seen", 0.0)))
    )

    parts: List[str] = []
    total = 0
    for idx, pg in enumerate(pages_sorted, 1):
        title = (pg.get("title") or "").strip() or "(no title)"
        url = (pg.get("url") or "").strip() or "(no url)"
        snippet = pg.get("snippet") or ""
        active = float(pg.get("active_seconds", 0.0))
        active_int = int(round(active))

        header_line = f"[{idx}] ({active_int}s) {title} - {url}"
        entry_text = header_line + "\n" + snippet + "\n"

        if total + len(entry_text) > max_chars:
            break

        parts.append(entry_text)
        total += len(entry_text)

    return "\n\n".join(parts)


def generate_session_recap_from_learning(
    pages_text: str,
    time_span_desc: str,
    total_time_seconds: float,
    top_title: Optional[str],
) -> str:
    total_minutes = total_time_seconds / 60.0
    total_time_str = f"{total_minutes:.1f} minutes" if total_minutes >= 1.0 else f"{int(total_time_seconds)} seconds"

    top_focus_line = (
        f"The page you spent the most time on was: '{top_title}'"
        if top_title
        else "You glanced at a few different topics without one clear favorite."
    )

    query = f"""
TIME WINDOW:
{time_span_desc}

TOTAL ACTIVE READING TIME (approx):
{total_time_str}

FOCUS HINT:
{top_focus_line}

INFORMATIVE PAGES (most time spent first):
{pages_text[:8000]}

TASK:
Write a short 'study session recap' based ONLY on the information above.

Do three things in ONE response:

1) Start with one sentence like:
   "In {time_span_desc}, you..." describing the main theme(s) the user
   was reading / learning about, and optionally mention the main page
   they focused on.

2) Then give 2-5 bullet points (lines starting with "- ") that list the
   most important ideas, facts, or techniques they encountered, phrased
   in simple language like a friendly tutor reminding them.

3) End with one short self-care / next-steps sentence, suggesting they
   rest, hydrate, or review specific topics next time.

Rules:
- Focus on what they learned, NOT on what websites they visited.
- Use the time hints as a proxy for what they cared most about.
- If some but not all pages have very little time, you can safely ignore them.
- Max 220 words total.
- Plain ASCII only. No Markdown headers, just simple text and "-" bullets.
- Tone: light, encouraging, slightly witty, not flirty.
"""
    resp = generate(
        model="us.meta.llama3-2-1b-instruct-v1:0",
        system="""
You are a concise, encouraging study companion.
You see only noisy text snippets from pages the user read, plus rough time spent.
Infer the main themes and key ideas, then remind them clearly but briefly.
""",
        query=query,
        temperature=0.3,
        lastk=0,
        session_id="LearnSessionRecap",
        rag_usage=False,
    )
    return resp["response"]

# -------------------------------------------------------------------
# Injection snippet
# -------------------------------------------------------------------

def make_injection_snippet(page_id: str) -> str:
    host = request.host
    return f"""
<div hidden id="llm-chat-id">{page_id}</div>
<link rel="stylesheet" href="http://{host}/web-static/widget.css" />
<script>
if (window.top !== window.self) {{
    console.debug("[LLM Widget] Removed because the page is an iframe.");
}}
else {{
  window.LLM_WIDGET_CONFIG = {{
    pageId: "{page_id}",
    apiBase: "http://{host}",
    staticBase: "http://{host}/static-assets"
  }};
  (function() {{
    var root = document.getElementById("llm-widget-root");
    if (!root) {{
      root = document.createElement("div");
      root.id = "llm-widget-root";
      document.body.appendChild(root);
    }}
    var s = document.createElement("script");
    s.src = "http://{host}/web-static/widget.js";
    s.async = true;
    document.head.appendChild(s);
  }})();
  }}
</script>
"""

def make_page_id(method: str, url: str, host: str) -> str:
    """
    Deterministic ID for a given (method, url, host) so the same page
    reuses the same page_id, enabling stable caches and timing.
    """
    key = f"{method.upper()} {host} {url}"
    h = hashlib.sha256(key.encode("utf-8")).hexdigest()
    return h[:32]


@app.post("/inject-resp")
def inject_resp():
    raw = request.get_data(cache=False)
    if not raw:
        return Response("Empty input", status=400)

    header_bytes, body_bytes = split_http_response(raw)
    first_line, headers = parse_headers(header_bytes)
    norm_headers = {k.lower(): v for k, v in headers.items()}

    ctype = norm_headers.get("content-type", "")
    ctype_l = ctype.lower()
    enc = norm_headers.get("content-encoding", "").lower()
    te = norm_headers.get("transfer-encoding", "").lower()

    method = request.args.get("method", "GET")
    raw_req_url = request.args.get("req_url", "")
    req_url = raw_req_url
    if " HTTP/" in req_url:
        req_url = req_url.split(" HTTP/", 1)[0]

    is_html = ("text/html" in ctype_l) or ("application/xhtml+xml" in ctype_l)

    supported_encoding = (
        enc == ""
        or "gzip" in enc
        or "deflate" in enc
        or ("br" in enc and brotli is not None)
    )

    if (not is_html) or (not supported_encoding):
        return Response(
            raw,
            content_type=ctype or "application/octet-stream",
        )

    body_plain = body_bytes
    decoded = False

    if "chunked" in te:
        try:
            body_plain = dechunk_body(body_plain)
            decoded = True
        except Exception as e:
            print("[inject-resp] Failed to dechunk body:", repr(e))
            return Response(
                raw,
                content_type=ctype or "application/octet-stream",
            )

    try:
        if "gzip" in enc:
            body_plain = gzip.decompress(body_plain)
            decoded = True
        elif "deflate" in enc:
            body_plain = zlib.decompress(body_plain)
            decoded = True
        elif "br" in enc and brotli is not None:
            body_plain = brotli.decompress(body_plain)
            decoded = True

    except Exception as e:
        print("[inject-resp] Failed to decompress body:", repr(e))
        return Response(
            raw,
            content_type=ctype or "application/octet-stream",
        )

    html = body_plain.decode("utf-8", errors="ignore")
    if not looks_like_html(html):
        print("[inject-resp] Skipping injection: body does not look like HTML")
        return Response(
            raw,
            content_type=ctype or "application/octet-stream",
        )

    host = request.host or ""
    page_id = make_page_id(method, req_url, host)
    print(f"page_id={page_id} for {method} {req_url}")

    store_page(page_id, html)
    try:
        append_learn_page(page_id, req_url, html)
    except Exception as e:
        print("[learn-stash] failed to append:", repr(e))

    snippet = make_injection_snippet(page_id)
    modified_html = inject_before_body_end(html, snippet)
    new_body = modified_html.encode("utf-8")

    out_headers = dict(norm_headers)
    out_headers.pop("content-security-policy", None)
    out_headers.pop("content-length", None)
    out_headers.pop("transfer-encoding", None)

    if decoded:
        out_headers.pop("content-encoding", None)

    out_headers["content-length"] = str(len(new_body))

    parts = [first_line]
    for k, v in out_headers.items():
        parts.append(f"{k}: {v}")
    header_blob = "\r\n".join(parts).encode("utf-8") + b"\r\n\r\n"

    final = header_blob + new_body
    print(f"Page injection success for page_id:{page_id}")
    return Response(final, content_type="application/octet-stream")


@app.get("/web-static/<path:filename>")
def static_files(filename):
    resp = send_from_directory(STATIC_DIR, filename)
    resp.headers["Cross-Origin-Resource-Policy"] = "cross-origin"
    return resp


@app.get("/static-assets/<path:filename>")
def static_assets(filename):
    resp = send_from_directory(ASSETS_DIR, filename)
    resp.headers["Cross-Origin-Resource-Policy"] = "cross-origin"
    return resp


@app.get("/health")
def health():
    return "ok"


@app.get("/page-comment")
async def page_comment():
    """
    Returns commentary for a given page_id.
    - By default, uses an in-memory cache keyed by page_id.
    - If ?force=true is passed, regenerates the comment and overwrites the cache.
    """
    page_id = request.args.get("id")
    if not page_id:
        return jsonify({"status": "error", "error": "missing id"}), 400

    force = request.args.get("force", "false").lower() == "true"

    if not force:
        # use cache first
        with COMMENT_LOCK:
            cached = COMMENT_CACHE.get(page_id)
        if cached is not None:
            return jsonify({
                "status": "done",
                "comment": cached,
                "from_cache": True,
            })
    html = get_page(page_id)
    if not html:
        return jsonify({"status": "error", "error": "missing page"}), 404

    comment = await asyncio.to_thread(llm_comment, html)

    with COMMENT_LOCK:
        COMMENT_CACHE[page_id] = comment

    return jsonify({
        "status": "done",
        "comment": comment,
        "from_cache": False,
    })


@app.post("/page-active")
def page_active():
    data = request.get_json(force=True, silent=True) or {}
    page_id = data.get("page_id")
    try:
        delta_seconds = float(data.get("delta_seconds") or 0.0)
    except (TypeError, ValueError):
        delta_seconds = 0.0

    if not page_id or delta_seconds <= 0.0:
        return jsonify({"status": "ignored", "reason": "invalid"}), 200

    global SESSION_RUNNING
    if not SESSION_RUNNING:
        return jsonify({"status": "ignored", "reason": "no_active_session"}), 200

    add_active_time(page_id, delta_seconds)
    return jsonify({"status": "ok"}), 200


@app.route("/widget-pos", methods=["GET"])
def get_widget_pos():
    return jsonify(avatar_pos), 200


@app.route("/widget-pos", methods=["POST"])
def set_widget_pos():
    data = request.get_json(force=True, silent=True) or {}
    left = data.get("left")
    bottom = data.get("bottom")

    if not isinstance(left, (int, float)) or not isinstance(bottom, (int, float)):
        return jsonify({"error": "invalid position"}), 400

    avatar_pos["left"] = float(left)
    avatar_pos["bottom"] = float(bottom)
    return jsonify({"status": "ok"}), 200


@app.route("/widget-state", methods=["GET"])
def get_widget_state():
    global SESSION_RUNNING
    return jsonify({
        "left": float(avatar_pos.get("left", 120.0)),
        "bottom": float(avatar_pos.get("bottom", 80.0)),
        "session_running": bool(SESSION_RUNNING),
    }), 200


@app.post("/session-start")
def session_start():
    start_session()
    return jsonify({"status": "ok"}), 200


@app.get("/session-recap")
async def session_recap():
    active_map = get_active_time()

    if not active_map:
        return jsonify({
            "status": "no_history",
            "recap": "I haven't seen you learn or read anything interesting yet this session.",
            "updated_at": None,
        })

    pages_with_time: List[Dict[str, Any]] = []
    min_ts = None
    max_ts = None
    total_active = 0.0

    for page_id, active_seconds in active_map.items():
        rec = get_learn_record_for_page(page_id) or {
            "page_id": page_id,
            "url": "",
            "title": "",
            "snippet": "",
            "ts_first_seen": time.time(),
        }

        ts = float(rec.get("ts_first_seen", time.time()))
        if min_ts is None or ts < min_ts:
            min_ts = ts
        if max_ts is None or ts > max_ts:
            max_ts = ts

        active = float(active_seconds)
        total_active += active

        new_pg = dict(rec)
        new_pg["active_seconds"] = active
        pages_with_time.append(new_pg)

    # filter out pages with very little reading time if we have at least one
    candidates = [
        p for p in pages_with_time
        if p.get("active_seconds", 0.0) >= MIN_READ_SECONDS
    ]
    if candidates:
        pages_for_recap = candidates
    else:
        pages_for_recap = pages_with_time

    if min_ts is not None and max_ts is not None and max_ts >= min_ts:
        span_seconds = max_ts - min_ts
        time_span_desc = describe_time_span(span_seconds)
    else:
        time_span_desc = "this session"

    if pages_for_recap:
        top_page = max(
            pages_for_recap,
            key=lambda p: float(p.get("active_seconds", 0.0)),
        )
        top_title = (top_page.get("title") or "").strip() or top_page.get("url") or None
    else:
        top_title = None

    pages_text = build_learning_context(pages_for_recap)

    recap_text = await asyncio.to_thread(
        generate_session_recap_from_learning,
        pages_text,
        time_span_desc,
        total_active,
        top_title,
    )
    now_ts = time.time()

    end_session()

    return jsonify({
        "status": "done",
        "recap": recap_text,
        "updated_at": now_ts,
    })

PORT = 8080

if __name__ == "__main__":
    print(f"LLM server starting at {PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False)
