"""
ANTS Packet Filter Module

This module provides HTTP flow processing and logging functionality with compression handling.
For development history and commented code examples, see:
docs/packet_filter_reference.md
"""
from mitmproxy import ctx, http
from mitmproxy.net.http import headers
from pathlib import Path
import json
import base64
from datetime import datetime, date
import zlib
import gzip
import sys
import os

# Add parent directory to path to import from rules and model packages
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# --- Setup for external dependencies ---
try:
    from rules.security_rules import STATIC_RULES
except ImportError:
    # Dummy rule for testing if file is missing
    STATIC_RULES = [("ExampleTag", lambda req: "example.com" in req.host)] 

try:
    from model.analyzer_factory import AnalyzerFactory
    from model.gemini_analyzer import GeminiAnalyzer
    
    # Initialize analyzer
    analyzer = GeminiAnalyzer()
    
    def analyze(context):
        """Wrapper function to maintain compatibility with existing code."""
        # Convert context to the format expected by the new analyzer
        content = f"""Host: {context.get('request_host', 'unknown')}
Summary: {json.dumps(context.get('summary', {}), indent=2)}
Request Payload: {context.get('request_payload_snippet', '')}
Response Payload: {context.get('response_payload_snippet', '')}"""
        
        result = analyzer.analyze_content(content)
        
        # Convert result to match expected format
        return {
            "risk_level": result.get("decision", "allow").capitalize(),
            "recommended_action": result.get("reason", "No analysis available"),
            "severity": result.get("severity", 0),
            "tags": result.get("tags", [])
        }
        
except ImportError as e:
    # Dummy analyze function if LLM backend is missing
    def analyze(context):
        return {"risk_level": "None", "recommended_action": "Ignore", "severity": 0, "tags": []}
        
OUT_DIR = Path.cwd() / "mitm_logs"
OUT_DIR.mkdir(parents=True, exist_ok=True)

# --- HELPER FUNCTIONS ---

def _get_body_text_or_b64(message):
    """
    Returns a text/base64 tuple for the request body.
    (Not used in final response logic but kept for completeness).
    """
    content = message.content or b""
    if not content:
        return True, ""
    try:
        text = content.decode('utf-8')
        return True, text
    except Exception:
        b64 = base64.b64encode(content).decode('ascii')
        return False, b64

def _get_clean_payload(flow):
    """
    Returns the decoded, uncompressed response body payload as a string.
    Handles gzip, deflate, and zlib encoding for robustness.
    """
    resp = flow.response
    if not resp or not resp.content:
        return ""

    content = resp.content
    content_encoding = resp.headers.get("Content-Encoding", "").lower()
    
    try:
        # 1. Decompress if necessary
        if content_encoding == "gzip":
            content = gzip.decompress(content)
        elif content_encoding == "deflate":
            content = zlib.decompress(content)
        elif content_encoding == "zlib":
            content = zlib.decompress(content, 16 + zlib.MAX_WBITS)
        
        # 2. Decode bytes to text
        return content.decode('utf-8', errors='replace')
        
    except Exception as e:
        # Fallback for unhandled compression or decoding errors
        ctx.log.warn(f"Failed to decompress or decode payload. Returning snippet: {e}")
        # Return base64 snippet of the raw content
        return base64.b64encode(resp.content[:512]).decode('ascii') + "..."

# --- EXTRACTION LOGIC ---

def extract_summary(flow):
    """
    Extracts a security-focused summary from an HTTP flow.
    """
    req = flow.request
    resp = flow.response
    
    SENSITIVE_HEADERS = ["Authorization", "Cookie", "X-Api-Key", "Client-Id", "AuthMsaDeviceTicket", "APIKey"]
    ATTACK_VECTORS = ["q", "id", "data", "callback", "redirect_to", "cmd"]
    
    # Check response body size
    resp_length = int(resp.headers.get("Content-Length", 0)) if resp and resp.headers.get("Content-Length") else len(resp.content) if resp and resp.content else 0
    
    # --- FIX FOR TIMESTAMP ERRORS: Calculate duration using explicit timestamps ---
    flow_duration = None
    start_time = req.timestamp_start if req else None
    end_time = resp.timestamp_end if resp else None

    if start_time and end_time:
        try:
            # Duration from request start until response finishes
            flow_duration = int((end_time - start_time) * 1000)
        except TypeError:
            pass
    # --- END FIX ---
    
    def check_suspicious_params(req):
        for param, value in req.query.items():
            if not isinstance(value, str):
                continue
            if any(keyword in value.lower() for keyword in ["select", "union", "sleep(", "file_get_contents", "<script"]):
                return True
            if param.lower() in ATTACK_VECTORS and len(value) > 200:
                 return True
        return False

    return {
        # --- Core Request/Response Info ---
        "host": req.host,
        "path": req.path,
        "method": req.method,
        "status_code": resp.status_code if resp else None,
        
        # --- Size and Timing ---
        "req_content_length": int(req.headers.get("Content-Length", 0)),
        "resp_content_length": resp_length,
        "flow_duration_ms": flow_duration, # Corrected field
        "req_start_time": datetime.fromtimestamp(start_time).isoformat() if start_time else None,

        # --- User/Identity Indicators ---
        "user_agent": req.headers.get("User-Agent", "Missing"),
        "has_sensitive_header": any(h in req.headers for h in SENSITIVE_HEADERS),
        
        # --- Attack Vector Indicators ---
        "content_type": req.headers.get("Content-Type", None),
        "is_unusual_content_type": req.headers.get("Content-Type", "").lower() not in ["application/json", "application/x-www-form-urlencoded", "multipart/form-data", "text/html", "application/bond-compact-binary", "application/web3s+xml"],
        "has_suspicious_query_params": check_suspicious_params(req),
        
        # --- Custom Tags/Rules ---
        "tags": [
            tag for tag, rule in STATIC_RULES if rule(req)
        ],
    }

# --- MITMPROXY HOOK ---

def response(flow: http.HTTPFlow) -> None:
    """Handles the response event, extracts summary, runs LLM analysis, and logs results."""
    try:
        # 1) Apply static rule matching and get compact summary
        summary = extract_summary(flow)
        tags = summary["tags"]

        # 2) Save compact summary always (for overall traffic visualization)
        summary_file = OUT_DIR / f"summary-{date.today().isoformat()}.jsonl"
        with open(summary_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(summary, ensure_ascii=False) + "\n")

        # Skip LLM and detailed logging if no tags matched
        if not tags:
            ctx.log.info(f"[OK]  {summary['host']} {summary['path']}")
            return

        # --- Triage and Log Alerted Traffic ---

        # Get the fully decompressed and decoded payload for analysis
        clean_payload = _get_clean_payload(flow) 
        
        # 3) Call LLM analysis (only tagged traffic)
        llm_context = {
            "summary": summary,
            "request_host": flow.request.host,
            # Pass a small snippet of the request payload
            "request_payload_snippet": flow.request.content[:512].decode('utf-8', errors='replace') + "..." if flow.request.content else "",
            # Pass a small snippet of the clean, readable response payload
            "response_payload_snippet": clean_payload[:2048] 
        }
        
        llm_result = analyze(llm_context)
        # llm_result = None
        print(llm_result)
        summary["analysis"] = llm_result

        # 4) Save LLM results to separate file
        alert_file = OUT_DIR / f"alerts-{date.today().isoformat()}.jsonl"
        with open(alert_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(summary, ensure_ascii=False) + "\n")

        # 5) Save MINIMAL raw flow packet with CLEAN PAYLOAD (for incident deep dive)
        raw_file = OUT_DIR / f"full-{date.today().isoformat()}.jsonl"
        
        # Define a focused set of headers to log
        MINIMAL_HEADERS_TO_LOG = ["Content-Type", "User-Agent", "Authorization", "X-MachineId", "Scenario", "Accept-Encoding"]
        
        minimal_raw = {
            # Use the flow's request start time as the general timestamp
            "timestamp": datetime.fromtimestamp(flow.request.timestamp_start).isoformat() if flow.request.timestamp_start else None,
            "flow_id": flow.id,
            "host": flow.request.host,
            "path": flow.request.path,
            "tags_matched": tags,
            "response_status": flow.response.status_code,
            # Log only critical/custom headers
            "request_headers_snippet": {k: str(v) for k, v in flow.request.headers.items() if k in MINIMAL_HEADERS_TO_LOG or k.startswith("X-") or len(k) < 15},
            "response_headers_snippet": {k: str(v) for k, v in flow.response.headers.items() if k in MINIMAL_HEADERS_TO_LOG or k.startswith("X-") or len(k) < 15},
            # The readable, decompressed content for full inspection
            "response_payload_decoded": clean_payload 
        }
        # print(minimal_raw)
        with open(raw_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(minimal_raw, default=str) + "\n")

        # 6) Log clear console status
        ctx.log.alert(
            f"[ALERT] {summary['host']} tags={tags} → risk={llm_result['risk_level']} "
            f"action={llm_result['recommended_action']}"
        )

    except Exception as e:
        # Use flow.id to identify which flow failed
        ctx.log.error(f"response() failure on flow {flow.id}: {e}")