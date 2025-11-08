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
# Assuming flow has a .request attribute with .host, .headers
# and the STATIC_RULES list is available in the scope.

# # --- RULE DEFINITIONS ---

# def rule_auth_token_leak(req):
#     # Rule 1 (Critical): Checks for sensitive headers
#     # Threat: Information Disclosure (ID)
#     return any(h in req.headers for h in [
#         "Authorization", "APIKey", "Auth", "AuthMsaDeviceTicket", "Bearer", "client-secret"
#     ])

# def rule_large_upload(req):
#     # Rule 2 (High): Checks for large Content-Length (Potential data exfiltration/DoS)
#     # Threat: Denial of Service (DoS), Information Disclosure (ID - Exfiltration)
#     cl = req.headers.get("Content-Length", "0")
#     # Threshold set at 500 KB 
#     return cl.isdigit() and int(cl) > 500_000 

# def rule_tracking_telemetry(req):
#     # Rule 3 (Low): Checks for common telemetry/analytics keywords in the host
#     # Threat: Repudiation (R) - Unverified data transfer, ID
#     return any(x in req.host for x in [
#         "events", "collector", "analytics", "telemetry", "crash", "report", "log"
#     ])

# def rule_untrusted_domain(req):
#     # Rule 4 (Medium): Checks if the domain is not in a whitelist
#     # Threat: Spoofing (S), Information Disclosure (ID)
#     return "." in req.host and not req.host.endswith((
#         "google.com", "microsoft.com", "github.com", "windows.com", "gstatic.com", "apple.com", "cdn.com","gemini.google.com"
#     ))

# def rule_sensitive_file_access(req):
#     # Rule 5 (Critical): Paths commonly targeted for LFI or configuration leaks
#     # Threat: Information Disclosure (ID), Elevation of Privilege (E), Tampering (T)
#     paths_to_check = [
#         "/etc/passwd", "/.git/config", "/.env", "/wp-config.php", 
#         "/.bash_history", "/WEB-INF/web.xml", "/robots.txt"
#     ]
#     return any(p.lower() in req.path.lower() for p in paths_to_check)

# def rule_c2_indicators(req):
#     # Rule 6 (High): Looks for common Command and Control (C2) patterns
#     # Threat: Tampering (T), Information Disclosure (ID)
#     c2_patterns = ["/api/v1/ping", "/update", "/status", "/beacon", "/upload", "/download"]
#     return (
#         # Suspicious path pattern + POST method
#         any(p in req.path.lower() for p in c2_patterns) and 
#         req.method == "POST" and 
#         req.host not in ["api.microsoft.com", "clientservices.google.com"]
#     ) or (
#         # High entropy/encoded data in the URL (Base64 is common)
#         "base64" in req.path.lower() or len(req.path) > 200
#     )

# def rule_non_standard_port(req):
#     # Rule 7 (Medium): Beaconing or unauthorized service access often uses high-numbered ports.
#     # Threat: Information Disclosure (ID), Spoofing (S)
#     # We check for ports > 10000 that aren't common development/proxy ports (e.g., 8080/8443)
#     return req.port > 10000 and req.port not in [443, 80, 8080, 8443, 9000]

# def rule_internal_ip_reference(req):
#     # Rule 8 (Critical): Checks for internal IP addresses or reserved domains in query parameters (SSRF)
#     # Threat: Spoofing (S), Information Disclosure (ID)
#     internal_patterns = ["127.0.0.1", "localhost", "10.", "192.168.", "172.16.", "169.254."]
#     query_string = req.query.to_string()
#     return any(p in query_string for p in internal_patterns)

# def rule_suspicious_method(req):
#     # Rule 9 (High): Flags HTTP methods often used for reconnaissance or advanced attacks
#     # Threat: Tampering (T), Repudiation (R)
#     suspicious_methods = ["TRACE", "CONNECT", "PURGE", "SEARCH", "PROPFIND"]
#     return req.method in suspicious_methods

# def rule_xss_payload(req):
#     # Rule 10 (High): Detects common XSS payload indicators in the URL path or query
#     # Threat: Tampering (T), Elevation of Privilege (E)
#     xss_indicators = ["<script", "javascript:", "onload=", "onerror=", "alert(", "eval("]
#     # Check both path and query string for indicators
#     check_string = req.path.lower() + req.query.to_string().lower()
#     return any(i in check_string for i in xss_indicators)

# def rule_broad_accept_header(req):
#     # Rule 11 (Medium): Flags overly broad Accept headers, which can indicate ID probing
#     # Threat: Information Disclosure (ID)
#     accept_header = req.headers.get("Accept", "")
#     return "*/*" in accept_header or "application/octet-stream" in accept_header

# def rule_unexpected_user_agent(req):
#     # Rule 12 (Reject): Flags known non-browser User-Agents common in scanning/botnets
#     # Threat: Spoofing (S), Denial of Service (DoS)
#     ua = req.headers.get("User-Agent", "").lower()
#     malicious_uas = ["python-requests", "go-http-client", "curl/", "wpscan", "sqlmap", "nikto"]
#     return any(m in ua for m in malicious_uas)

# def rule_admin_path_probe(req):
#     # Rule 13 (Reject): Flags probing for known admin/security paths
#     # Threat: Elevation of Privilege (E), Spoofing (S)
#     probe_paths = ["/admin/", "/wp-admin", "/login.jsp", "/auth", "/security/"]
#     return any(p in req.path.lower() for p in probe_paths)

# def rule_high_entropy_query(req):
#     # Rule 14 (High): Checks for long, complex, and potentially encoded query strings (Tunneling/Exfiltration)
#     # Threat: Tampering (T), Information Disclosure (ID - Exfiltration), Repudiation (R)
#     query_string = req.query.to_string()
#     # A simplified heuristic: check for excessive length (over 100 chars) AND base64-like characters
#     if len(query_string) > 100:
#         base64_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
#         # Check if a high percentage of characters are base64-valid (proxy for high entropy)
#         valid_b64_count = sum(1 for char in query_string if char in base64_chars)
#         # If over 60% of the long query string is b64-like, it's highly suspicious
#         return (valid_b64_count / len(query_string)) > 0.6
#     return False

# def rule_binary_content_transfer(req):
#     # Rule 15 (High): Checks for suspicious content-type usage in non-GET requests
#     # Threat: Tampering (T), Information Disclosure (ID)
#     content_type = req.headers.get("Content-Type", "").lower()
#     return req.method != "GET" and (
#         # Binary data sent as text/plain
#         content_type == "text/plain" and len(req.content) > 1000 
#     )


# # --- STATIC RULES LIST ---

# STATIC_RULES = [
#     # Critical (ALERT)
#     ("auth_token_leak", rule_auth_token_leak),
#     ("sensitive_file_access", rule_sensitive_file_access),
#     ("internal_ip_reference", rule_internal_ip_reference), 

#     # High (BLOCK)
#     ("large_upload", rule_large_upload),
#     ("c2_indicators", rule_c2_indicators),
#     ("suspicious_method", rule_suspicious_method),       
#     ("xss_payload", rule_xss_payload),                   
#     ("high_entropy_query", rule_high_entropy_query),       # New Block Rule
#     ("binary_content_transfer", rule_binary_content_transfer), # New Block Rule

#     # Reject (REJECT)
#     ("unexpected_user_agent", rule_unexpected_user_agent), # New Reject Rule
#     ("admin_path_probe", rule_admin_path_probe),         # New Reject Rule

#     # Medium (WARN)
#     ("untrusted_domain", rule_untrusted_domain),
#     ("non_standard_port", rule_non_standard_port),
#     ("broad_accept_header", rule_broad_accept_header),    

#     # Low (LOG)
#     ("tracking_telemetry", rule_tracking_telemetry),
# ]

# # --- ACTION HIERARCHY MAPPING ---

# # Action Priority: ALERT > BLOCK > REJECT > WARN > LOG > ALLOW

# def rule_based_check(flow) -> dict:
#     """
#     Applies static rules to an HTTP flow and determines a priority security action.
#     """
#     req = flow.request
#     detected_tags = ["General"]
    
#     # 1. Check all rules and gather tags
#     for tag, rule in STATIC_RULES:
#         if rule(req):
#             detected_tags.append(tag)
    
#     # 2. Determine the highest-priority action
#     final_action = "ALLOW"
    
#     # Priority 1: Critical (ALERT)
#     if any(tag in detected_tags for tag in ["auth_token_leak", "sensitive_file_access", "internal_ip_reference"]):
#         final_action = "ALERT"
    
#     # Priority 2: Critical Mitigation (BLOCK)
#     elif any(tag in detected_tags for tag in ["large_upload", "c2_indicators", "suspicious_method", "xss_payload", "high_entropy_query", "binary_content_transfer"]):
#         final_action = "BLOCK"
        
#     # Priority 3: Policy Violation (REJECT)
#     elif any(tag in detected_tags for tag in ["unexpected_user_agent", "admin_path_probe"]):
#         final_action = "REJECT"

#     # Priority 4: Medium Suspicion (WARN)
#     elif any(tag in detected_tags for tag in ["untrusted_domain", "non_standard_port", "broad_accept_header"]):
#         final_action = "WARN"

#     # Priority 5: Low Suspicion (LOG)
#     elif "tracking_telemetry" in detected_tags:
#         final_action = "LOG"
            
#     # Note: If multiple rules trigger, the highest action in the priority list wins.
    
#     return {
#         "rule_action": final_action,
#         "triggered_rules": detected_tags,
#         "rule_explanation": f"Highest priority action is '{final_action}' based on triggered rules: {', '.join(detected_tags) if detected_tags else 'None'}"
#     }


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
