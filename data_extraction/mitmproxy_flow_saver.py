# mitmproxy -s mitmproxy_flow_saver.py --listen-host 0.0.0.0 -p 8080
from mitmproxy import ctx, http
from mitmproxy.net.http import headers
from pathlib import Path
import json
import base64
from datetime import datetime, date

OUT_DIR = Path(__file__).parent.parent / "logs" / "mitm_logs"
OUT_DIR.mkdir(parents=True, exist_ok=True)

def _get_body_text_or_b64(message):
    """
    Return a tuple (is_text, text_or_b64)
    - if body can be decoded to text, return (True, text)
    - otherwise return (False, base64_string)
    """
    content = message.content or b""
    if not content:
        return True, ""
    try:
        # try to decode as UTF-8 (most common)
        text = content.decode('utf-8')
        return True, text
    except Exception:
        b64 = base64.b64encode(content).decode('ascii')
        return False, b64

def response(flow: http.HTTPFlow) -> None:
    try:
        # Build a serializable dictionary
        req_text_ok, req_body = _get_body_text_or_b64(flow.request)
        resp_text_ok, resp_body = _get_body_text_or_b64(flow.response)

        entry = {
            "timestamp": datetime.utcfromtimestamp(flow.request.timestamp_start).isoformat() + "Z" if flow.request.timestamp_start else datetime.utcnow().isoformat() + "Z",
            "client": {
                "peername": list(flow.client_conn.peername) if getattr(flow.client_conn, "peername", None) else None,
                "sni": flow.server_conn.sni if getattr(flow, "server_conn", None) else None
            },
            "request": {
                "method": flow.request.method,
                "scheme": flow.request.scheme,
                "host": flow.request.host,
                "port": flow.request.port,
                "path": flow.request.path,
                "http_version": flow.request.http_version,
                "headers": dict(flow.request.headers),
                "body_is_text": bool(req_text_ok),
                "body": req_body
            },
            "response": {
                "status_code": flow.response.status_code,
                "reason": flow.response.reason,
                "http_version": flow.response.http_version,
                "headers": dict(flow.response.headers),
                "body_is_text": bool(resp_text_ok),
                "body": resp_body
            },
            "timings": {
                "request_start": flow.request.timestamp_start,
                "request_end": flow.request.timestamp_end,
                "response_start": flow.response.timestamp_start,
                "response_end": flow.response.timestamp_end
            },
            "flow_id": flow.id
        }

        # Daily rotated file name: mitm-YYYY-MM-DD.jsonl
        filename = OUT_DIR / f"mitm-{date.today().isoformat()}.jsonl"
        with open(filename, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

        # optional: log to mitmproxy console
        ctx.log.info(f"Saved flow {flow.id} -> {filename.name}")
    except Exception as e:
        # never crash mitmproxy from addon errors
        ctx.log.error(f"save_flows error: {e}")
