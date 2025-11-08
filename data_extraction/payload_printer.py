# print_payloads.py
# Usage: mitmdump -p 8080 -s print_payloads.py
# or: mitmproxy --mode regular -p 8080 -s print_payloads.py

from mitmproxy import http, ctx
import os
import hashlib
import time

# Maximum text body size we'll print to console (bytes)
MAX_PRINT = 100 * 1024  # 100 KB
# Directory to save large/binary bodies
DUMP_DIR = os.path.join(os.getcwd(), "mitm_dumps")
os.makedirs(DUMP_DIR, exist_ok=True)

TEXT_HINTS = ("text/", "application/json", "application/javascript",
              "application/xml", "application/x-www-form-urlencoded",
              "application/html")

def _is_likely_text(content_type: str, content: bytes) -> bool:
    if not content_type:
        # fallback heuristic: check if bytes look like UTF-8/text
        try:
            content.decode("utf-8")
            return True
        except Exception:
            return False
    ct = content_type.lower()
    if any(ct.startswith(h) for h in TEXT_HINTS):
        return True
    # some servers omit charset; try quick decode
    try:
        content.decode("utf-8")
        return True
    except Exception:
        return False

def _save_blob(prefix: str, content: bytes, content_type: str) -> str:
    # create filename with timestamp + hash
    h = hashlib.sha1(content).hexdigest()[:12]
    ts = int(time.time())
    safe_ct = (content_type.replace("/", "_").replace(";", "_") if content_type else "unknown")
    fname = f"{prefix}_{ts}_{h}_{safe_ct}.bin"
    fpath = os.path.join(DUMP_DIR, fname)
    with open(fpath, "wb") as f:
        f.write(content)
    return fpath

def _print_headers(headers):
    for k, v in headers.items():
        ctx.log.info(f"{k}: {v}")

def _try_get_text(content: bytes):
    if content is None:
        return None
    if len(content) == 0:
        return ""
    # try common encodings
    for enc in ("utf-8", "utf-8-sig", "latin-1", "ascii"):
        try:
            return content.decode(enc)
        except Exception:
            continue
    return None

def _print_body(prefix: str, content: bytes, content_type: str):
    if content is None or len(content) == 0:
        ctx.log.info(f"[{prefix}] (empty body)")
        return

    is_text = _is_likely_text(content_type, content)
    if is_text:
        txt = _try_get_text(content)
        if txt is None:
            # fallback: save binary
            fpath = _save_blob(prefix, content, content_type)
            ctx.log.info(f"[{prefix}] saved binary-ish body to: {fpath} (size={len(content)} bytes)")
            return
        if len(txt) > MAX_PRINT:
            # print head + save full
            ctx.log.info(f"[{prefix}] text body too large ({len(txt)} bytes). printing first {MAX_PRINT} chars:")
            ctx.log.info(txt[:MAX_PRINT])
            fpath = _save_blob(prefix, content, content_type)
            ctx.log.info(f"[{prefix}] full text body saved to: {fpath}")
        else:
            ctx.log.info(f"[{prefix}] (size={len(txt)} bytes):\n{txt}")
    else:
        fpath = _save_blob(prefix, content, content_type)
        ctx.log.info(f"[{prefix}] binary body saved to: {fpath} (size={len(content)} bytes, Content-Type={content_type})")

# mitmproxy event: called when request headers are received
def request(flow: http.HTTPFlow) -> None:
    r = flow.request
    ctx.log.info("=== REQUEST ===")
    ctx.log.info(f"{r.method} {r.scheme}://{r.host}{r.path}")
    _print_headers(r.headers)
    # get content-type header if present
    ct = r.headers.get("Content-Type", "")
    body = r.raw_content
    _print_body("Request", body, ct)
    ctx.log.info("=== END REQUEST ===\n")

# mitmproxy event: called when response headers are received
def response(flow: http.HTTPFlow) -> None:
    r = flow.response
    ctx.log.info("=== RESPONSE ===")
    ctx.log.info(f"{flow.request.method} {flow.request.scheme}://{flow.request.host}{flow.request.path} -> {r.status_code}")
    _print_headers(r.headers)
    ct = r.headers.get("Content-Type", "")
    body = r.raw_content
    _print_body("Response", body, ct)
    ctx.log.info("=== END RESPONSE ===\n")
