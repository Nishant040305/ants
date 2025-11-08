
# import os
# import json
# from openai import OpenAI
# from openai import APIError # Correct import path for API exceptions
# # from save_packet_filtered import extract_summary
# OPENAI_API_KEY = "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"

# # Initialize the OpenAI client
# # It is best practice to pass the key directly if not using os.getenv
# try:
#     client = OpenAI(api_key=key)
# except Exception as e:
#     print(f"Error initializing OpenAI client: {e}")
#     raise

# # --- 2. Prompt Definition (Enhanced for strict JSON output) ---
# # Assuming flow has a .request attribute with .host, .headers
# # and the STATIC_RULES list is available in the scope.

# # Define the STATIC_RULES (as provided by you)
# def rule_auth_token_leak(req):
#     # Rule 1: Checks for sensitive headers
#     return any(h in req.headers for h in [
#         "Authorization", "APIKey", "Auth", "AuthMsaDeviceTicket", "Bearer"
#     ])

# def rule_large_upload(req):
#     # Rule 2: Checks for large Content-Length (Potential data exfiltration/DoS)
#     cl = req.headers.get("Content-Length", "0")
#     return cl.isdigit() and int(cl) > 200_000 # 200 KB threshold

# def rule_tracking_telemetry(req):
#     # Rule 3: Checks for common telemetry/analytics keywords in the host
#     return any(x in req.host for x in [
#         "events", "collector", "analytics", "telemetry", "crash", "report"
#     ])

# def rule_untrusted_domain(req):
#     # Rule 4: Checks if the domain is not in a whitelist
#     return "." in req.host and not req.host.endswith((
#         "google.com", "microsoft.com", "github.com", "windows.com", "gstatic.com"
#     ))

# STATIC_RULES = [
#     ("auth_token_leak", rule_auth_token_leak),
#     ("large_upload", rule_large_upload),
#     ("tracking_telemetry", rule_tracking_telemetry),
#     ("untrusted_domain", rule_untrusted_domain),
# ]

# # Define the action hierarchy: Critical rules first
# ACTION_MAPPING = {
#     # High Priority: Malicious or sensitive activity
#     "auth_token_leak": "ALERT",
#     "large_upload": "BLOCK",
    
#     # Medium Priority: Suspicious or unverified activity
#     "untrusted_domain": "WARN",
    
#     # Low Priority: Informational/Normal but requires logging
#     "tracking_telemetry": "LOG",
# }

# def rule_based_check(flow) -> dict:
#     """
#     Applies static rules to an HTTP flow and determines a priority security action.
#     Action Priority: ALERT > BLOCK > REJECT > WARN > LOG > ALLOW
#     """
#     req = flow.request
#     detected_tags = []
    
#     # 1. Check all rules and gather tags
#     for tag, rule in STATIC_RULES:
#         if rule(req):
#             detected_tags.append(tag)
    
#     # 2. Determine the highest-priority action
#     final_action = "ALLOW"
    
#     # Check for critical alerts first
#     if "auth_token_leak" in detected_tags:
#         final_action = "ALERT"
#     elif "large_upload" in detected_tags:
#         final_action = "BLOCK"
#     elif "untrusted_domain" in detected_tags:
#         # If already ALERT or BLOCK, don't downgrade.
#         if final_action == "ALLOW":
#             final_action = "WARN"
#     elif "tracking_telemetry" in detected_tags:
#         # LOG is the lowest priority action, but still supersedes ALLOW if no other rules fire
#         if final_action == "ALLOW":
#             final_action = "LOG"
            
#     # Note: If multiple rules trigger, the highest action in the priority list wins.
    
#     return {
#         "rule_action": final_action,
#         "triggered_rules": detected_tags,
#         "rule_explanation": f"Highest priority action is '{final_action}' based on triggered rules: {', '.join(detected_tags) if detected_tags else 'None'}"
#     }
# def extract_summary(flow):
#     """
#     Extracts a security-focused summary from an HTTP flow.
#     Includes key indicators for detecting malicious or anomalous traffic.
#     """
#     req = flow.request
#     resp = flow.response
    
#     # Heuristic for checking for credentials/sensitive tokens
#     SENSITIVE_HEADERS = ["Authorization", "Cookie", "X-Api-Key", "Client-Id"]
    
#     # Heuristic for common injection or attack parameters
#     ATTACK_VECTORS = ["q", "id", "data", "callback", "redirect_to", "cmd"]
    
#     # Function to check for large response body size (potential data exfiltration)
#     resp_length = int(resp.headers.get("Content-Length", 0)) if resp and resp.headers.get("Content-Length") else len(resp.content) if resp and resp.content else 0

#     # Function to check for suspicious query parameters
#     def check_suspicious_params(req):
#         for param, value in req.query.items():
#             # Check for common SQL/XSS/Command injection keywords in values
#             if any(keyword in value.lower() for keyword in ["select", "union", "sleep(", "file_get_contents", "<script"]):
#                 return True
#             # Check for overly long or binary-looking values in common injection parameters
#             if param.lower() in ATTACK_VECTORS and len(value) > 200:
#                  return True
#         return False

#     return {
#         # --- Core Request/Response Info ---
#         "host": req.host,
#         "path": req.path,
#         "method": req.method,
#         "status_code": resp.status_code if resp else None,
        
#         # --- Size and Timing (Exfiltration/DOS Indicators) ---
#         "req_content_length": int(req.headers.get("Content-Length", 0)),
#         "resp_content_length": resp_length,
#         "flow_duration_ms": int((flow.end_time - flow.timestamp) * 1000) if flow.end_time else None,

#         # --- User/Identity Indicators ---
#         "user_agent": req.headers.get("User-Agent", "Missing"),
#         "cookies_present": 'Cookie' in req.headers,
#         "has_sensitive_header": any(h in req.headers for h in SENSITIVE_HEADERS),
        
#         # --- Attack Vector Indicators ---
#         "content_type": req.headers.get("Content-Type", None),
#         "is_unusual_content_type": req.headers.get("Content-Type", "").lower() not in ["application/json", "application/x-www-form-urlencoded", "multipart/form-data", "text/html"],
#         "has_suspicious_query_params": check_suspicious_params(req),
        
#         # --- Custom Tags/Rules (Keep original logic) ---
#         "tags": [
#             tag for tag, rule in STATIC_RULES if rule(req) # STATIC_RULES must be defined elsewhere
#         ],
#     }
# PROMPT = """
# You are a highly skilled cybersecurity network analyst.
# Analyze the provided HTTP flow summary in JSON format.
# Your analysis must be contextual and your entire response MUST be a single JSON object.

# Flow Summary to Analyze:
# {payload}

# Return JSON only, adhering strictly to the following schema:
# {{
#   "llm_risk_level": "low|medium|high|critical",
#   "llm_explanation": "A concise, contextual summary of the risk and traffic findings.",
#   "llm_recommended_action": "One of: ALLOW, BLOCK, REJECT, LOG, WARN, or ALERT."
# }}
# """

# # --- 3. Analysis Function (With error handling) ---

# # Recommended standard model for fast, accurate JSON output:
# MODEL_NAME = "gpt-4o-mini"

# def analyze(summary: dict) -> dict:
#     """
#     Analyzes a security-focused flow summary using the OpenAI LLM 
#     and returns a structured JSON analysis.
#     """
#     try:
#         summary = extract_summary(summary)
#         # Format the prompt with the flow data
#         text = PROMPT.format(payload=json.dumps(summary, ensure_ascii=False, indent=2))
        
#         # Call the OpenAI Chat Completions API
#         res = client.chat.completions.create(
#             model=MODEL_NAME,
#             messages=[{"role": "user", "content": text}],
#             temperature=0.0,
#             response_format={"type": "json_object"}
#         )

#         # The model's content should be pure JSON due to response_format setting
#         content = res.choices[0].message.content
        
#         # Parse the JSON string into a Python dictionary
#         return json.loads(content)
        
#     except APIError as e:
#         print(f"OpenAI API Error: {e}")
#         return {"llm_risk_level": "critical", "llm_explanation": f"OpenAI API call failed: {e}", "llm_recommended_action": "ALERT"}
#     except json.JSONDecodeError:
#         print(f"JSON Decoding Error: Model output was not valid JSON. Raw Output: {content}")
#         return {"llm_risk_level": "critical", "llm_explanation": "Model failed to return valid JSON output.", "llm_recommended_action": "ALERT"}
#     except Exception as e:
#         print(f"An unexpected error occurred: {e}")
#         return {"llm_risk_level": "critical", "llm_explanation": f"Unexpected error: {e}", "llm_recommended_action": "ALERT"}


# if __name__ == "__main__":
#     test_flow_summary = {
#         "host": "bad-domain-transfer.ru",
#         "path": "/exfil/data?id=123",
#         "method": "POST",
#         "req_content_length": 500000,  # 500 KB upload
#         "has_auth_header": True,
#         "tags": ["large_upload", "untrusted_domain"],
#         # ... (include all fields from your extract_summary function)
#     }

#     print("--- Running OpenAI Analysis ---")
#     analysis_result = analyze(test_flow_summary)
#     print(json.dumps(analysis_result, indent=2))


#!/usr/bin/env python3
"""
analyze_mtim_log.py

Read HTTP flow records from mtim_log.jsonl (one JSON object per line),
extract security summaries, call the OpenAI LLM for a JSON analysis,
and save the results to mtim_analysis_results.jsonl.

Requirements:
    pip install openai
    (or whichever client your environment uses; this script uses `from openai import OpenAI`)

Usage:
    export OPENAI_API_KEY="sk-..."
    python analyze_mtim_log.py
"""

import os
import json
import time
import traceback
from typing import Any, Dict, Optional

# Use your OpenAI client module. The script below uses the same import style you used.
# Install the package that provides `OpenAI` if needed.
try:
    from openai import OpenAI
    from openai import APIError
except Exception:
    # Fallback message - user may need to pip install openai
    raise RuntimeError("Please install/update the openai package so `from openai import OpenAI` works.")

# ------------------------
# Config
# ------------------------
INPUT_FILE = "mitm-logs.jsonl"
OUTPUT_FILE = "mtim_analysis_results.jsonl"
MODEL_NAME = "gpt-4o-mini"  # from your original script
MAX_RETRIES = 4
RETRY_BASE_SECONDS = 1.0  # exponential backoff base

# ------------------------
# Helper lightweight classes that mimic the interface expected by your functions.
# The original code expects `flow.request`, `flow.response`, `flow.timestamp`, `flow.end_time`.
# We'll wrap each JSON record into these small objects so your extract_summary(rule_based_check, analyze) work.
# ------------------------
class SimpleRequest:
    def __init__(self, data: Dict[str, Any]):
        # expected fields: host, path, method, headers (dict), query (dict), content (str), timestamp, etc.
        self.host = data.get("host", "")
        self.path = data.get("path", "")
        self.method = data.get("method", data.get("req_method", "GET"))
        # normalize headers to dict (case-sensitive as your rules check)
        self.headers = data.get("headers", {}) or {}
        # query can be dict or encoded string; assume dict
        self.query = data.get("query", {}) or {}
        self.content = data.get("content", "")
        # allow Content-Length in either headers or top-level field
        if "Content-Length" not in self.headers and "req_content_length" in data:
            self.headers["Content-Length"] = str(data.get("req_content_length", 0))

class SimpleResponse:
    def __init__(self, data: Dict[str, Any]):
        # fields: status_code, headers, content
        self.status_code = data.get("status_code", data.get("resp_status", None))
        self.headers = data.get("headers", {}) or {}
        self.content = data.get("content", b"")  # may be bytes or string

class FlowWrapper:
    def __init__(self, rec: Dict[str, Any]):
        # rec is the dict parsed from JSON line in mtim_log.jsonl
        # adapt to likely field names; be permissive
        self.raw = rec
        self.request = SimpleRequest(rec)
        self.response = SimpleResponse(rec.get("response", {}) if isinstance(rec.get("response", {}), dict) else rec)
        # timestamps may be present; default to current time if absent
        # Expect timestamps in seconds (unix epoch) or in ISO string - but we will try numeric first
        ts = rec.get("timestamp") or rec.get("start_time") or rec.get("flow_start")
        end_ts = rec.get("end_time") or rec.get("flow_end")
        try:
            self.timestamp = float(ts) if ts is not None else time.time()
        except Exception:
            # if timestamp is string, let it be current time
            self.timestamp = time.time()
        try:
            self.end_time = float(end_ts) if end_ts is not None else None
        except Exception:
            self.end_time = None

# ------------------------
# Your static rule functions and extract_summary() - copied and slightly hardened for missing keys
# ------------------------
def rule_auth_token_leak(req):
    return any(h in req.headers for h in [
        "Authorization", "APIKey", "Auth", "AuthMsaDeviceTicket", "Bearer"
    ])

def rule_large_upload(req):
    cl = req.headers.get("Content-Length", "0")
    try:
        return cl.isdigit() and int(cl) > 200_000
    except Exception:
        return False

def rule_tracking_telemetry(req):
    return any(x in (req.host or "") for x in [
        "events", "collector", "analytics", "telemetry", "crash", "report"
    ])

def rule_untrusted_domain(req):
    host = req.host or ""
    return "." in host and not host.endswith((
        "google.com", "microsoft.com", "github.com", "windows.com", "gstatic.com"
    ))

STATIC_RULES = [
    ("auth_token_leak", rule_auth_token_leak),
    ("large_upload", rule_large_upload),
    ("tracking_telemetry", rule_tracking_telemetry),
    ("untrusted_domain", rule_untrusted_domain),
]

ACTION_MAPPING = {
    "auth_token_leak": "ALERT",
    "large_upload": "BLOCK",
    "untrusted_domain": "WARN",
    "tracking_telemetry": "LOG",
}

def rule_based_check(flow) -> dict:
    req = flow.request
    detected_tags = []
    for tag, rule in STATIC_RULES:
        try:
            if rule(req):
                detected_tags.append(tag)
        except Exception:
            # If a rule fails, ignore it but continue
            continue

    final_action = "ALLOW"
    if "auth_token_leak" in detected_tags:
        final_action = "ALERT"
    elif "large_upload" in detected_tags:
        final_action = "BLOCK"
    elif "untrusted_domain" in detected_tags:
        if final_action == "ALLOW":
            final_action = "WARN"
    elif "tracking_telemetry" in detected_tags:
        if final_action == "ALLOW":
            final_action = "LOG"

    return {
        "rule_action": final_action,
        "triggered_rules": detected_tags,
        "rule_explanation": f"Highest priority action is '{final_action}' based on triggered rules: {', '.join(detected_tags) if detected_tags else 'None'}"
    }

def extract_summary(flow):
    req = flow.request
    resp = flow.response

    SENSITIVE_HEADERS = ["Authorization", "Cookie", "X-Api-Key", "Client-Id"]
    ATTACK_VECTORS = ["q", "id", "data", "callback", "redirect_to", "cmd"]

    # compute resp_length
    resp_length = 0
    try:
        if resp and isinstance(resp.headers, dict) and resp.headers.get("Content-Length"):
            resp_length = int(resp.headers.get("Content-Length", 0))
        elif resp and hasattr(resp, "content") and resp.content:
            resp_length = len(resp.content) if isinstance(resp.content, (bytes, str)) else 0
    except Exception:
        resp_length = 0

    def check_suspicious_params(req):
        try:
            for param, value in (req.query.items() if isinstance(req.query, dict) else []):
                if not isinstance(value, str):
                    value = str(value)
                if any(keyword in value.lower() for keyword in ["select", "union", "sleep(", "file_get_contents", "<script"]):
                    return True
                if param.lower() in ATTACK_VECTORS and len(value) > 200:
                    return True
        except Exception:
            return False
        return False

    tags = []
    for tag, rule in STATIC_RULES:
        try:
            if rule(req):
                tags.append(tag)
        except Exception:
            continue

    # req_content_length: try headers, then raw fields
    try:
        req_content_length = int(req.headers.get("Content-Length", 0))
    except Exception:
        req_content_length = 0

    return {
        "host": req.host,
        "path": req.path,
        "method": req.method,
        "status_code": resp.status_code if resp and hasattr(resp, "status_code") else None,
        "req_content_length": req_content_length,
        "resp_content_length": resp_length,
        "flow_duration_ms": int((flow.end_time - flow.timestamp) * 1000) if getattr(flow, "end_time", None) else None,
        "user_agent": req.headers.get("User-Agent", "Missing"),
        "cookies_present": 'Cookie' in req.headers,
        "has_sensitive_header": any(h in req.headers for h in SENSITIVE_HEADERS),
        "content_type": req.headers.get("Content-Type", None),
        "is_unusual_content_type": req.headers.get("Content-Type", "").lower() not in ["application/json", "application/x-www-form-urlencoded", "multipart/form-data", "text/html"],
        "has_suspicious_query_params": check_suspicious_params(req),
        "tags": tags,
    }

# ------------------------
# LLM / OpenAI interaction
# ------------------------
def make_openai_client():
    # key = os.getenv("OPENAI_API_KEY")
    # if not key:
    #     raise RuntimeError("OPENAI_API_KEY is not set in environment. Set it before running this script.")
    # instantiate client - pass api_key directly as in original code
    return OpenAI(api_key="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")

PROMPT_TEMPLATE = """
You are a highly skilled cybersecurity network analyst.
Analyze the provided HTTP flow summary in JSON format.
Your analysis must be contextual and your entire response MUST be a single JSON object.

Flow Summary to Analyze:
{payload}

Return JSON only, adhering strictly to the following schema:
{{
  "llm_risk_level": "low|medium|high|critical",
  "llm_explanation": "A concise, contextual summary of the risk and traffic findings.",
  "llm_recommended_action": "One of: ALLOW, BLOCK, REJECT, LOG, WARN, or ALERT."
}}
"""

def call_llm_analyze(client: OpenAI, summary: dict) -> dict:
    """
    Calls the OpenAI chat completion API to analyze `summary`.
    Returns the parsed JSON result or raises an Exception.
    """
    prompt_text = PROMPT_TEMPLATE.format(payload=json.dumps(summary, ensure_ascii=False, indent=2))
    # Try multiple retries with exponential backoff on transient errors
    attempt = 0
    last_exc = None
    while attempt <= MAX_RETRIES:
        try:
            attempt += 1
            res = client.chat.completions.create(
                model=MODEL_NAME,
                messages=[{"role": "user", "content": prompt_text}],
                temperature=0.0,
                # Using response_format may or may not be supported in your client version.
                # Keep it but also robustly parse content if the library doesn't honor it.
                response_format={"type": "json_object"}
            )
            # Extract content
            content = None
            try:
                content = res.choices[0].message.content
            except Exception:
                # Some client versions return .choices[0].text
                content = getattr(res.choices[0], "text", None)
            if content is None:
                raise ValueError("LLM returned empty content")
            # content should be JSON string; parse it.
            if isinstance(content, dict):
                # If the client already parsed JSON (some versions), return directly
                return content
            parsed = json.loads(content)
            return parsed
        except APIError as api_e:
            last_exc = api_e
            # backoff for retriable API errors
            if attempt <= MAX_RETRIES:
                sleep = RETRY_BASE_SECONDS * (2 ** (attempt - 1))
                time.sleep(sleep)
                continue
            raise
        except json.JSONDecodeError as jerr:
            # The model didn't return valid JSON — capture raw content if available and raise
            raise RuntimeError(f"LLM returned invalid JSON: {jerr}\nRaw content: {content}") from jerr
        except Exception as e:
            last_exc = e
            if attempt <= MAX_RETRIES:
                time.sleep(RETRY_BASE_SECONDS * (2 ** (attempt - 1)))
                continue
            raise
    # If we exit loop without returning, raise the last exception
    raise last_exc or RuntimeError("LLM call failed without specific exception")

# ------------------------
# Main processing loop
# ------------------------
def process_file(input_path: str, output_path: str):
    client = make_openai_client()
    processed = 0
    with open(input_path, "r", encoding="utf-8") as inf, \
         open(output_path, "a", encoding="utf-8") as outf:
        for line in inf:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                # skip malformed line
                continue

            flow = FlowWrapper(rec)

            # 1) produce programmatic summary with your function
            try:
                summary = extract_summary(flow)
            except Exception as e:
                # fallback: minimal summary so LLM still runs
                summary = {
                    "host": getattr(flow.request, "host", ""),
                    "path": getattr(flow.request, "path", ""),
                    "method": getattr(flow.request, "method", ""),
                    "req_content_length": 0,
                    "resp_content_length": 0,
                    "tags": []
                }

            # 2) apply rule-based check
            try:
                rules = rule_based_check(flow)
            except Exception as e:
                rules = {"rule_action": "ALLOW", "triggered_rules": [], "rule_explanation": "rule check failed"}

            # enrich summary with rule verdict
            summary["_rule_verdict"] = rules

            # 3) call LLM for deeper analysis
            llm_result = None
            # try:
            #     # llm_result = call_llm_analyze(client, summary)
            # except Exception as e:
            #     # On any LLM failure, record the failure in llm_result
            #     llm_result = {
            #         "llm_risk_level": "critical",
            #         "llm_explanation": f"LLM call failed: {str(e)}",
            #         "llm_recommended_action": "ALERT"
            #     }

            # Consolidate result
            out_rec = {
                "flow_raw": rec,
                "summary": summary,
                "rules": rules,
                "llm": llm_result,
                "processed_at": time.time()
            }

            # Write as JSONL line
            outf.write(json.dumps(out_rec, ensure_ascii=False) + "\n")
            outf.flush()
            processed += 1

    print(f"Done. Processed {processed} flows. Output appended to: {output_path}")

# ------------------------
# Entry point
# ------------------------
if __name__ == "__main__":
    if not os.path.exists(INPUT_FILE):
        print(f"Input file '{INPUT_FILE}' not found in current dir. Create/put your mtim_log.jsonl there.")
    else:
        try:
            process_file(INPUT_FILE, OUTPUT_FILE)
        except Exception as e:
            print("Fatal error during processing:")
            traceback.print_exc()
            raise
