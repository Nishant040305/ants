Excellent — this is a powerful, demo-friendly, hackathon-grade plan. Below I give a complete, self-contained specification you can implement in 36–48 hours: architecture, concrete mitmproxy script, the LLM prompt + schema for context-aware classification, severity scoring rubric, logging/alert format, UI/UX suggestions, performance & safety considerations, demo script, and the exact pitfalls you must disclose to judges.

I assume Windows demo machine with mitmproxy + Chrome (you’ll install mitmproxy CA) and an LLM endpoint (either a hosted API key you control, or a local Llama/llama.cpp HTTP wrapper). Replace placeholders with your keys.

---

# 1 — High-level Architecture (One Diagram, Textual)

* **mitmproxy** (local machine; acts as TLS MITM with installed root CA)

  * Intercepts all HTTP/S traffic, terminates TLS.
  * For each request & response, extracts request/response headers and bodies (textual only).
  * Calls local classifier + LLM service (sync or async) to create a security assessment (context-aware).
  * Based on policy & LLM result: log, alert (desktop), block, redact, or forward unchanged.
* **LLM Security Analyzer** (local service or hosted)

  * Receives structured payload (request/response metadata + contextual info) and returns JSON: tags, severity, reasoning, suggested action, PBOM-like metadata.
* **Dashboard / Collector**

  * Stores events (e.g., Elasticsearch/SQLite), shows timeline, search, and alerting UI.
* **Agent (optional)**

  * Tray app that displays immediate alerts and allows user to accept/release blocked requests.

Flow: Client App → mitmproxy → LLM Analyzer → Decision → Upstream / Block / Redact → Log/Alert.

---

# 2 — Feasibility & Constraints (Be Honest)

* **Feasible:** For most browser and many native apps that respect system proxy and trust user-installed CAs. You can analyze plaintext payloads in mitmproxy and call an LLM for context-aware classification.
* **Limitations:** Apps with certificate pinning will bypass MITM. Real-time LLM calls add latency — mitigate with caching, fast local models, or async triage. Must disclose legal/ethical requirement to run only on consenting demo systems. Don’t attempt to MITM mobile apps in public networks without explicit consent.

---

# 3 — Enforcement Modes (What the proxy can do)

* **LOG-ONLY:** Annotate and forward (safe, demo-friendly).
* **ALERT:** Show desktop notification and store event.
* **REDACT:** Modify body to redact sensitive fields before forwarding (e.g., replace tokens with `***REDACTED***`).
* **BLOCK:** Return HTTP 403 with explanation.
* **ROUTE:** Instead of cloud upstream, route to local model or sandboxed endpoint.

For hackathon demo: implement LOG-ONLY + ALERT + REDACT (blocking is dramatic but must be careful).

---

# 4 — Concrete mitmproxy Script (Python) — Full Example

Save as `ai_guard_mitm.py`. It demonstrates:

* Inspecting request and response bodies (textual).
* Building a context payload.
* Calling an LLM analyzer (placeholder HTTP call).
* Acting on LLM output (log, alert, redact, block).

```python
# ai_guard_mitm.py
from mitmproxy import http, ctx
import json, base64, re, time, requests, threading, sqlite3
from html import unescape

# === CONFIGURATION ===
LLM_ANALYZER_URL = "http://127.0.0.1:5001/analyze"  # your LLM analyzer endpoint
ALERT_THRESHOLD = 6    # severity >= this => alert
REDACT_THRESHOLD = 8   # severity >= this => redact sensitive values in payload
BLOCK_THRESHOLD = 10   # severity >= this => block request (use carefully)

# Storage (simple sqlite for events)
DB_PATH = "events.db"

# Only inspect textual content types
TEXT_CT = ("application/json","application/x-www-form-urlencoded","text/","application/xml","multipart/form-data")

# quick heuristic to avoid huge binary blobs
MAX_BODY_LEN = 20000

# === UTILITIES ===
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS events
                   (ts REAL, id TEXT, host TEXT, path TEXT, direction TEXT, severity INTEGER, tags TEXT, decision TEXT, reason TEXT)''')
    conn.commit()
    conn.close()

def store_event(e):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?)",
                (e["ts"], e["id"], e["host"], e["path"], e["direction"], e["severity"], json.dumps(e["tags"]), e["decision"], e["reason"]))
    conn.commit()
    conn.close()

def is_textual(flow):
    ct = flow.request.headers.get("content-type","")
    if any(t in ct for t in TEXT_CT):
        return True
    # also check response content-types
    ct2 = flow.response.headers.get("content-type","") if flow.response else ""
    if any(t in ct2 for t in TEXT_CT):
        return True
    return False

def safe_get_body_text(flow, which="request"):
    try:
        if which == "request":
            raw = flow.request.get_text()
        else:
            raw = flow.response.get_text()
        # some pages return binary or huge; guard:
        if not raw or len(raw) > MAX_BODY_LEN:
            return ""
        return raw
    except Exception:
        return ""

# === LLM CALL ===
def call_llm_analyzer(payload):
    # blocking call - keep small for demo; in prod use async thread pool
    try:
        resp = requests.post(LLM_ANALYZER_URL, json=payload, timeout=8)
        if resp.status_code == 200:
            return resp.json()
        else:
            ctx.log.warn(f"LLM analyzer returned {resp.status_code}")
            return {"severity":0,"tags":[],"decision":"allow","reason":"analyzer_error"}
    except Exception as e:
        ctx.log.warn(f"LLM analyzer error: {e}")
        return {"severity":0,"tags":[],"decision":"allow","reason":"analyzer_unreachable"}

# === REDACTION HELPERS ===
TOKEN_RE = re.compile(r'(sk-[A-Za-z0-9-_]{16,}|[A-Za-z0-9_]{24}\.[A-Za-z0-9_]{6}\.[A-Za-z0-9_-]{27}|[\w-]{24}\.[\w-]{6}\.[\w-]{27})')  # common token patterns
APIKEY_RE = re.compile(r'(AKIA[0-9A-Z]{16})|([A-Za-z0-9]{32,})')

def redact_text(text, tags):
    # simple redaction: replace tokens / obvious secrets
    text = TOKEN_RE.sub("[REDACTED_TOKEN]", text)
    text = APIKEY_RE.sub("[REDACTED_KEY]", text)
    # optionally redact emails if classification demands
    if "email_in_message" in tags or "email_sensitive" in tags:
        text = re.sub(r'[\w\.-]+@[\w\.-]+', "[REDACTED_EMAIL]", text)
    return text

# === MAIN HOOKS ===
import uuid
def request(flow: http.HTTPFlow):
    if not is_textual(flow):
        return
    body = safe_get_body_text(flow, "request")
    if not body:
        return

    # Build context
    payload = {
        "id": str(uuid.uuid4()),
        "ts": time.time(),
        "direction": "request",
        "host": flow.request.host,
        "path": flow.request.path,
        "method": flow.request.method,
        "headers": dict(flow.request.headers),
        "body": body,
        "source": "mitmproxy",
    }

    # Call LLM (blocking). For speed, could do async threading with immediate logging.
    analysis = call_llm_analyzer(payload)

    # analysis expected: {"severity": int, "tags": [...], "decision": "allow|alert|redact|block", "reason": "explain"}
    severity = int(analysis.get("severity",0))
    tags = analysis.get("tags",[])
    decision = analysis.get("decision","allow")
    reason = analysis.get("reason","")

    # store event
    event = {"ts": payload["ts"], "id": payload["id"], "host": payload["host"], "path": payload["path"],
             "direction": "request", "severity": severity, "tags": tags, "decision": decision, "reason": reason}
    store_event(event)

    # enforcement
    if severity >= BLOCK_THRESHOLD or decision == "block":
        flow.response = http.HTTPResponse.make(403, b"Blocked by AI Supply Chain Firewall", {"Content-Type":"text/plain"})
        ctx.log.warn(f"Blocked request to {flow.request.host}{flow.request.path} reason:{reason}")
        return

    if severity >= REDACT_THRESHOLD or decision == "redact":
        newbody = redact_text(body, tags)
        flow.request.set_text(newbody)
        ctx.log.info(f"Redacted request to {flow.request.host}{flow.request.path} tags:{tags}")

    if severity >= ALERT_THRESHOLD or decision == "alert":
        # lightweight alert: add header and log
        flow.request.headers.add("X-AI-SC-Alert", "true")
        ctx.log.warn(f"ALERT: host={flow.request.host} severity={severity} tags={tags} reason={reason}")

def response(flow: http.HTTPFlow):
    # Inspect responses similarly for sensitive leakage in responses (e.g., server echoes tokens)
    if not flow.response:
        return
    if not is_textual(flow):
        return
    body = safe_get_body_text(flow, "response")
    if not body:
        return

    payload = {
        "id": str(uuid.uuid4()),
        "ts": time.time(),
        "direction": "response",
        "host": flow.request.host,
        "path": flow.request.path,
        "status_code": flow.response.status_code,
        "headers": dict(flow.response.headers),
        "body": body,
        "source": "mitmproxy",
    }

    analysis = call_llm_analyzer(payload)
    severity = int(analysis.get("severity",0))
    tags = analysis.get("tags",[])
    decision = analysis.get("decision","allow")
    reason = analysis.get("reason","")
    event = {"ts": payload["ts"], "id": payload["id"], "host": payload["host"], "path": payload["path"],
             "direction": "response", "severity": severity, "tags": tags, "decision": decision, "reason": reason}
    store_event(event)

    if severity >= REDACT_THRESHOLD or decision == "redact":
        newbody = redact_text(body, tags)
        flow.response.set_text(newbody)
        ctx.log.info(f"Redacted response from {flow.request.host} tags:{tags}")

    if severity >= ALERT_THRESHOLD or decision == "alert":
        ctx.log.warn(f"ALERT response: host={flow.request.host} severity={severity} tags={tags} reason={reason}")
```

**Notes on this script**

* It assumes an analyzer endpoint that returns a JSON with `severity`, `tags`, `decision`, `reason`.
* For performance, you will want to push LLM calls into a threadpool or use an async queue (see Performance section).
* The redaction functions are intentionally simple — for the hackathon, good heuristics work; for production you'd use structured parsers or JSON key-based redaction.

---

# 5 — LLM Analyzer: Input Schema, Prompt, And Expected Output

You must design the analyzer to be consistent and auditable. Below is a recommended JSON input and LLM system prompt + output schema.

## Analyzer Input (JSON)

```json
{
  "id": "uuid",
  "ts": 1700000000,
  "direction": "request",
  "host": "api.example.com",
  "path": "/v1/chat/completions",
  "method": "POST",
  "headers": { "content-type": "application/json", "authorization": "Bearer sk-xxx" },
  "body": "{... raw request body ...}",
  "source": "mitmproxy"
}
```

## LLM System Prompt (Fixed)

```
You are a security analyst assistant that inspects HTTP request/response payloads and detects sensitive or policy-violating content. Output must be JSON only and must follow the schema:

{
  "severity": <int 0-10>,
  "tags": [ "token_in_message", "token_in_header", "email_in_message", "creditcard", "discord_token", "personal_data", "sql_query", ... ],
  "decision": "allow" | "alert" | "redact" | "block",
  "redaction_candidates": [ { "type": "token", "span": [start, end] , "value": "..." } ],
  "reason": "<short human-readable reason>",
  "explain": "<one paragraph explanation>"
}

Rules:
- severity 0 = safe, 10 = certain data exfiltration / critical secret.
- Use tags to precisely tag what was found.
- If a token is present in headers and also in body, tag both "token_in_header" and "token_in_message".
- Consider context: a discord token value in a response header from discord.com may be fine, but the same token appearing in a user-sent message is a violation.
- If uncertain, be conservative: raise a higher severity and recommend "alert".
- Keep JSON strictly valid.
```

## Example Output

```json
{
  "severity": 9,
  "tags": ["discord_token", "token_in_message"],
  "decision": "block",
  "redaction_candidates": [{"type":"discord_token","span":[123,156],"value":"mfa.ABCD..."}],
  "reason": "A Discord token was found inside a user message body, indicating token leak.",
  "explain": "The payload contains a Discord authentication token inside the outbound message field. Tokens are sensitive credentials and must not be transmitted in message content; block and redact."
}
```

---

# 6 — Severity Scoring Rubric (Concrete)

Create deterministic rules that combine LLM confidence + heuristics:

* Base score by tag:

  * `token_in_header` → +6
  * `token_in_message` → +8
  * `discord_token` → +4
  * `api_key_pattern` → +5
  * `creditcard` → +8
  * `personal_data` → +4
  * `ssn` → +9
  * `email_in_message` → +2
  * `email_in_header` → +1
  * `sql_query` → +3
* Add context multipliers:

  * If token appears in both header and body → +3
  * If host is an upstream cloud LLM provider and content contains PII → +2
  * If the body is to a chat/send endpoint (heuristic by path) → +2
* Clamp severity to [0,10].
* Decision mapping:

  * severity 0-3 → allow
  * 4-6 → alert
  * 7-8 → redact + alert
  * 9-10 → block (demo caution: maybe use redact+alert instead)

Use LLM `explain` as tie-breaker and for human-readable logs.

---

# 7 — Examples: Context-Aware Cases

1. **Discord token in Authorization header to discord.com**

   * Tags: `discord_token`, `token_in_header`
   * Severity: 6 → `alert` (headers to official API can be OK if expected; log & monitor)

2. **Discord token found in POST message body to discord.com/api/channels/{id}/messages**

   * Tags: `discord_token`, `token_in_message`
   * Severity: 10 → `block` or `redact+alert` (definitely secret leakage)

3. **AWS Access Key found in JSON body to upstream LLM provider**

   * Tags: `aws_access_key`, `token_in_message`
   * Severity: 10 → block + alert, redact before logging

4. **Email address in message content to Slack (user message)**

   * Tags: `email_in_message`
   * Severity: 3 → allow but `alert` (low severity but policy might forbid PII)

---

# 8 — Logging / Event Schema (Stored)

Keep an auditable JSON log:

```json
{
  "event_id": "uuid",
  "ts": 1700000000,
  "direction": "request",
  "host": "api.example.com",
  "path": "/v1/chat",
  "severity": 9,
  "tags": ["token_in_message","discord_token"],
  "decision": "redact",
  "redactions": [{"type":"token","location":"body","replacement":"[REDACTED_TOKEN]"}],
  "raw_sample_hash": "sha256(...)",  // do not store raw sensitive content, store hash
  "explain": "...",
  "analyzer_version": "v0.1-llm"
}
```

Important: do **not** store raw secrets in logs. Store only hashes or redacted samples.

---

# 9 — Dashboard / UX (What Judges See)

* Real-time list of alerts with: timestamp, host, path, severity, tags, suggested action, one-line reasoning.
* Clicking an event shows full `explain` text from LLM and redaction candidates (user can approve release).
* Searchable by host, tag, severity.
* Live “blocked count”, “avg latency”, “LLM calls/second”.

Implement quick UI with a small Flask/Node app + Bootstrap and read events from the SQLite DB (good for hackathon).

---

# 10 — Performance & Cost Considerations

* LLM latency is the bottleneck. Mitigations:

  * Use a small local LLM for analyzer (e.g., Llama 2 local HTTP wrapper) for sub-second inference.
  * Cache repeated payload signatures (hash request body + host + path) to reuse analysis for identical requests.
  * Tiered analysis: quick heuristic first (regex/token patterns) to short-circuit; only call LLM for heuristics that need context.
  * Batch analyzers asynchronously and make enforcement conservative (e.g., allow+log if LLM timeout).
* Rate limits: guard your LLM provider; an attacker could flood proxy to exhaust credits. Add rate limit and circuit-breaker.

---

# 11 — Safety, Legal, and Ethics

* Explicitly warn and require consent: "Do not install MITM CA on machines you do not control."
* Use redaction for logs; never persist raw secrets.
* For demonstration: use a throwaway VM with only demo apps and an unprivileged test account.
* Disclose limitations: pinned apps, firmware-level capture, mobile apps that bypass system proxy.

---

# 12 — Quick Demo Plan (90–180 seconds, Impress Judges)

Prepare:

* VM with mitmproxy + CA installed and your dashboard open.
* Sample payloads (files) and a small page or curl commands to simulate leaking tokens.

Demo:

1. Start mitmproxy with `mitmproxy -s ai_guard_mitm.py -p 8080`. Show CA installed.
2. In browser, submit a harmless chat message -> show event logged severity 0-2 (allow).
3. Paste a sample `sk-` key into the chat input and send -> mitmproxy logs event with `token_in_message`, severity 9; dashboard shows alert; request is redacted or blocked; show LLM `explain`.
4. Show subtler case: same token inside JSON `authorization` header to `discord.com` → lower severity (alert only). Show LLM explanation that header is normal for that endpoint.
5. Show policy override: approve one event to forward (demonstrate agent UI).
6. Finish with slides describing scope, limitations, and next steps.

This demonstrates both *context awareness* and *actionable enforcement*.

---

# 13 — Implementation Checklist (36–48 Hours)

**Day 0 (Setup & Core)**

* [ ] Create Python environment; install mitmproxy, requests.
* [ ] Write `ai_guard_mitm.py` and test with simple text interception.
* [ ] Initialize SQLite DB and simple CLI viewer.

**Day 1 (LLM Analyzer + Integration)**

* [ ] Implement small LLM analyzer service (Flask) that wraps a local Llama or hosted API.
* [ ] Implement system prompt and output schema, test with canned payloads.
* [ ] Wire mitmproxy -> LLM calls, store events.

**Day 2 (Enforcement + Dashboard + UX)**

* [ ] Implement redaction and alert desktop notification (simple `os.system("msg")` or use Windows toast library).
* [ ] Build quick web dashboard that reads events DB.
* [ ] Prepare demo payloads and finalize 90s script.
* [ ] Write limitations slide and legal/consent warning.

---

# 14 — Extra: Quick LLM Analyzer Flask Stub (for local Llama or OpenAI)

```python
# analyzer_server.py
from flask import Flask, request, jsonify
import re, json, time

app = Flask(__name__)

SENSITIVE_RE = re.compile(r'(sk-|AKIA|-----BEGIN PRIVATE KEY-----)', re.I)

@app.route("/analyze", methods=["POST"])
def analyze():
    payload = request.json
    body = payload.get("body","")
    tags = []
    severity = 0
    reason = "no issues detected"
    if SENSITIVE_RE.search(body):
        tags.append("token_in_message")
        severity += 8
        reason = "Detected token pattern in message body"
    # embed call to real LLM here or heuristics
    # if integrating OpenAI or local Llama, call and parse model output here
    decision = "allow"
    if severity >= 9:
        decision = "redact"
    elif severity >= 6:
        decision = "alert"
    return jsonify({"severity":severity, "tags":tags, "decision":decision, "reason":reason, "explain":"heuristic result"})

if __name__ == "__main__":
    app.run(port=5001)
```

Replace heuristic logic with a real LLM call once the flow is validated.

---

# 15 — Final Notes / Pitch Lines For Judges

* “We detect and stop contextual secret leaks in real time by reading the traffic on-device and using an LLM to reason about *context* — not just patterns.”
* “This isn’t a static DLP: the LLM understands whether a token inside a header is expected, or the same token inside a message body is an exfiltration.”
* “We log only hashes and redacted content — privacy-first. We show explainable reasoning with each alert so human ops can quickly respond.”

---

If you want, I will right now:

1. Produce a slightly more advanced mitmproxy script that batches LLM calls asynchronously and caches analyses (for speed), **or**
2. Expand the LLM system prompt with a long list of tags and examples to maximize classification quality, **or**
3. Create the minimal Flask + example local Llama call code (toy) integrated into the pipeline.

Pick 1, 2, or 3 and I’ll generate the code immediately.
