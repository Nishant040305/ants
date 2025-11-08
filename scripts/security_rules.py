"""
ANTS Security Rules Engine

This module provides HTTP security rule definitions and action prioritization.
For detailed rule documentation and development history, see:
docs/security_rules_reference.md
"""

from urllib.parse import urlencode

# --- Utility Safe Query String Conversion ---
def get_query_string(req):
    try:
        return urlencode(list(req.query.items()))
    except:
        return str(req.query)

# --- RULE DEFINITIONS ---

def rule_auth_token_leak(req):
    return any(h in req.headers for h in [
        "Authorization", "APIKey", "Auth", "AuthMsaDeviceTicket", "Bearer", "client-secret"
    ])

def rule_large_upload(req):
    cl = req.headers.get("Content-Length", "0")
    return cl.isdigit() and int(cl) > 500_000 

def rule_tracking_telemetry(req):
    return any(x in req.host for x in [
        "events", "collector", "analytics", "telemetry", "crash", "report", "log"
    ])

def rule_untrusted_domain(req):
    return "." in req.host and not req.host.endswith((
        "google.com", "microsoft.com", "github.com", "windows.com",
        "gstatic.com", "apple.com", "cdn.com", "gemini.google.com"
    ))

def rule_sensitive_file_access(req):
    paths_to_check = [
        "/etc/passwd", "/.git/config", "/.env", "/wp-config.php", 
        "/.bash_history", "/WEB-INF/web.xml", "/robots.txt"
    ]
    return any(p.lower() in req.path.lower() for p in paths_to_check)

def rule_c2_indicators(req):
    c2_patterns = ["/api/v1/ping", "/update", "/status", "/beacon", "/upload", "/download"]
    return (
        any(p in req.path.lower() for p in c2_patterns) and 
        req.method == "POST"
    ) or (
        "base64" in req.path.lower() or len(req.path) > 200
    )

def rule_non_standard_port(req):
    return req.port > 10000 and req.port not in [443, 80, 8080, 8443, 9000]

def rule_internal_ip_reference(req):
    internal_patterns = ["127.0.0.1", "localhost", "10.", "192.168.", "172.16.", "169.254."]
    query_string = get_query_string(req)
    return any(p in query_string for p in internal_patterns)

def rule_suspicious_method(req):
    return req.method in ["TRACE", "CONNECT", "PURGE", "SEARCH", "PROPFIND"]

def rule_xss_payload(req):
    query_string = get_query_string(req).lower()
    path = req.path.lower()
    xss_indicators = ["<script", "javascript:", "onload=", "onerror=", "alert(", "eval("]
    return any(i in path or i in query_string for i in xss_indicators)

def rule_broad_accept_header(req):
    accept_header = req.headers.get("Accept", "")
    return "*/*" in accept_header or "application/octet-stream" in accept_header

def rule_unexpected_user_agent(req):
    ua = req.headers.get("User-Agent", "").lower()
    malicious_uas = ["python-requests", "go-http-client", "curl/", "wpscan", "sqlmap", "nikto"]
    return any(m in ua for m in malicious_uas)

def rule_admin_path_probe(req):
    probe_paths = ["/admin/", "/wp-admin", "/login.jsp", "/auth", "/security/"]
    return any(p in req.path.lower() for p in probe_paths)

def rule_high_entropy_query(req):
    query_string = get_query_string(req)
    if len(query_string) > 100:
        base64_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
        valid_b64_count = sum(1 for char in query_string if char in base64_chars)
        return (valid_b64_count / len(query_string)) > 0.6
    return False

def rule_binary_content_transfer(req):
    content_type = req.headers.get("Content-Type", "").lower()
    content_len = len(req.content) if req.content else 0
    return req.method != "GET" and (content_type == "text/plain" and content_len > 1000)


# --- STATIC RULES LIST ---

STATIC_RULES = [
    ("auth_token_leak", rule_auth_token_leak),
    ("sensitive_file_access", rule_sensitive_file_access),
    ("internal_ip_reference", rule_internal_ip_reference),

    ("large_upload", rule_large_upload),
    ("c2_indicators", rule_c2_indicators),
    ("suspicious_method", rule_suspicious_method),
    ("xss_payload", rule_xss_payload),
    ("high_entropy_query", rule_high_entropy_query),
    ("binary_content_transfer", rule_binary_content_transfer),

    ("unexpected_user_agent", rule_unexpected_user_agent),
    ("admin_path_probe", rule_admin_path_probe),

    ("untrusted_domain", rule_untrusted_domain),
    ("non_standard_port", rule_non_standard_port),
    ("broad_accept_header", rule_broad_accept_header),

    ("tracking_telemetry", rule_tracking_telemetry),
]

# --- ACTION ENGINE ---

def rule_based_check(flow) -> dict:
    req = flow.request
    detected_tags = []

    for tag, rule in STATIC_RULES:
        if rule(req):
            detected_tags.append(tag)

    final_action = "ALLOW"

    if any(t in detected_tags for t in ["auth_token_leak", "sensitive_file_access", "internal_ip_reference"]):
        final_action = "ALERT"

    elif any(t in detected_tags for t in ["large_upload","c2_indicators","suspicious_method","xss_payload","high_entropy_query","binary_content_transfer"]):
        final_action = "BLOCK"

    elif any(t in detected_tags for t in ["unexpected_user_agent","admin_path_probe"]):
        final_action = "REJECT"

    elif any(t in detected_tags for t in ["untrusted_domain","non_standard_port","broad_accept_header"]):
        final_action = "WARN"

    elif "tracking_telemetry" in detected_tags:
        final_action = "LOG"

    return {
        "rule_action": final_action,
        "triggered_rules": detected_tags,
        "rule_explanation": f"{final_action} triggered by: {', '.join(detected_tags) if detected_tags else 'None'}"
    }
