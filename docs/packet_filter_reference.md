# Save Packet Filtered Development Reference

This document contains the commented code and development iterations extracted from `save_packet_filtered.py` during the project cleanup.

## Version 1 - Basic Save Flows Implementation

```python
# save_flows.py
from mitmproxy import ctx, http
from mitmproxy.net.http import headers
from pathlib import Path
import json
import base64
from datetime import datetime, date
from static_rules import STATIC_RULES
from llm_backend.llm_gemini import analyze
OUT_DIR = Path.cwd() / "mitm_logs"
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

# def extract_summary(flow):
#     req = flow.request
#     resp = flow.response

#     return {
#         "host": req.host,
#         "path": req.path,
#         "method": req.method,
#         "content_type": req.headers.get("Content-Type", None),
#         "content_length": int(req.headers.get("Content-Length", 0)),
#         "status_code": resp.status_code if resp else None,
#         "has_credentials": any(h in req.headers for h in ["Authorization", "APIKey", "AuthMsaDeviceTicket"]),
#         "client_id": req.headers.get("Client-Id", None),
#         "sdk_version": req.headers.get("SDK-Version", None),
#         "tags": [
#             tag for tag, rule in STATIC_RULES if rule(req)
#         ],
#     }

# def response(flow: http.HTTPFlow) -> None:
#     try:
#         # Only keep flows that match rules
#         summary = extract_summary(flow)
#         if not summary["tags"]:
#             return  # ignore noise

#         # Save only compact summary line
#         filename = OUT_DIR / f"summary-{date.today().isoformat()}.jsonl"
#         with open(filename, "a", encoding="utf-8") as f:
#             f.write(json.dumps(summary, ensure_ascii=False) + "\n")

#         ctx.log.info(f"[FILTERED] {summary['host']} {summary['path']} tags={summary['tags']}")
#     except Exception as e:
#         ctx.log.error(f"summary logging error: {e}")
```

## Version 2 - Enhanced Security-Focused Summary

```python
def extract_summary(flow):
    """
    Extracts a security-focused summary from an HTTP flow.
    Includes key indicators for detecting malicious or anomalous traffic.
    """
    req = flow.request
    resp = flow.response
    
    # Heuristic for checking for credentials/sensitive tokens
    SENSITIVE_HEADERS = ["Authorization", "Cookie", "X-Api-Key", "Client-Id"]
    
    # Heuristic for common injection or attack parameters
    ATTACK_VECTORS = ["q", "id", "data", "callback", "redirect_to", "cmd"]
    
    # Function to check for large response body size (potential data exfiltration)
    resp_length = int(resp.headers.get("Content-Length", 0)) if resp and resp.headers.get("Content-Length") else len(resp.content) if resp and resp.content else 0

    # Function to check for suspicious query parameters
    def check_suspicious_params(req):
        for param, value in req.query.items():
            # Check for common SQL/XSS/Command injection keywords in values
            if any(keyword in value.lower() for keyword in ["select", "union", "sleep(", "file_get_contents", "<script"]):
                return True
            # Check for overly long or binary-looking values in common injection parameters
            if param.lower() in ATTACK_VECTORS and len(value) > 200:
                 return True
        return False

    return {
        # --- Core Request/Response Info ---
        "host": req.host,
        "path": req.path,
        "method": req.method,
        "status_code": resp.status_code if resp else None,
        
        # --- Size and Timing (Exfiltration/DOS Indicators) ---
        "req_content_length": int(req.headers.get("Content-Length", 0)),
        "resp_content_length": resp_length,
        "flow_duration_ms": int((flow.end_time - flow.timestamp) * 1000) if flow.end_time else None,

        # --- User/Identity Indicators ---
        "user_agent": req.headers.get("User-Agent", "Missing"),
        "cookies_present": 'Cookie' in req.headers,
        "has_sensitive_header": any(h in req.headers for h in SENSITIVE_HEADERS),
        
        # --- Attack Vector Indicators ---
        "content_type": req.headers.get("Content-Type", None),
        "is_unusual_content_type": req.headers.get("Content-Type", "").lower() not in ["application/json", "application/x-www-form-urlencoded", "multipart/form-data", "text/html"],
        "has_suspicious_query_params": check_suspicious_params(req),
        
        # --- Custom Tags/Rules (Keep original logic) ---
        "tags": [
            tag for tag, rule in STATIC_RULES if rule(req) # STATIC_RULES must be defined elsewhere
        ],
    }
```

## Version 3 - Comprehensive Analysis Pipeline

```python
def response(flow: http.HTTPFlow) -> None:
    try:
        # ------------------------------
        # 1) Apply static rule matching
        # ------------------------------
        summary = extract_summary(flow)
        tags = summary["tags"]

        # ------------------------------
        # 2) Save compact summary always
        # ------------------------------
        summary_file = OUT_DIR / f"summary-{date.today().isoformat()}.jsonl"
        with open(summary_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(summary, ensure_ascii=False) + "\n")

        # If no tags → skip LLM + skip full logging
        if not tags:
            ctx.log.info(f"[OK]  {summary['host']} {summary['path']}")
            return

        # ------------------------------
        # 3) Call LLM analysis (only tagged traffic)
        # ------------------------------
        llm_result = analyze(summary)  # returns dict

        summary["analysis"] = llm_result

        # ------------------------------
        # 4) Save LLM results to separate file
        # ------------------------------
        alert_file = OUT_DIR / f"alerts-{date.today().isoformat()}.jsonl"
        with open(alert_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(summary, ensure_ascii=False) + "\n")

        # ------------------------------
        # 5) Save full raw flow packet (only for flagged flows)
        # ------------------------------
        raw_file = OUT_DIR / f"full-{date.today().isoformat()}.jsonl"
        raw = flow.get_state()  # this captures full request+response safely

        with open(raw_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(raw, default=str) + "\n")

        # ------------------------------
        # 6) Log clear console status
        # ------------------------------
        ctx.log.alert(
            f"[ALERT] {summary['host']} tags={tags} → risk={llm_result['risk_level']} "
            f"action={llm_result['recommended_action']}"
        )

    except Exception as e:
        ctx.log.error(f"response() failure: {e}")
```

## Sample Flow Example (Commented Out)

```python
# flow = {"timestamp": "2025-11-07T22:07:01.000268Z", "client": {"peername": ["127.0.0.1", 54367], "sni": "201667-ipv4fdsmte.gr.global.aa-rt.sharepoint.com"}, "request": {"method": "GET", "scheme": "https", "host": "201667-ipv4fdsmte.gr.global.aa-rt.sharepoint.com", "port": 443, "path": "/personal/FB0E114B901691BD/_api/SPFileSync/sync/5d2445a6f48d4f6cb190640d11e29a93/RootFolder?siteHost=my.microsoftpersonalcontent.com&Filter=changes&InlineBlobs=false&MaxItemCount=500&SyncToken=4;%234;%231;3;5d2445a6-f48d-4f6c-b190-640d11e29a93;638981500170970000;832324005;%23;%23;%230;%23&View=SkyDriveSync", "http_version": "HTTP/1.1", "headers": {"Connection": "Keep-Alive", "Accept": "application/web3s+xml", "Accept-Encoding": "gzip", "Accept-Language": "en-IN", "Authorization": "WLID1.1 t=EwA4BN1JBAAUGRcwizD/253wQ5plOzO+sy+X2JgAAWjCYMesmSRRbsobbZ5Lf31yWO77TAkP12eiiVvq6ZnYUXkXSd/TKnqAj8Qt+/S5ErN31FZaYOf4prreu9qotwSO/gK7LgH/nf459bd5hI+3KB34j1Z/7hVnYn5nSuo4/gOP+eLsPueS56OiH/Yoew47But26MyYsm8xFTUApkMTBtZQqHlWmlGoQLfSpn5KupUaDzjHoa1+8Bo+1hLr4UiDeZazIXcDP25LhiB0BCENbTzQhY/PxPvgLzwJoLaNNzltgCTTWhq9wl1BpCQOAcXsWdNoCBVgfAUNlhTb++RVdIV3q3EvzKuONbRoE7p90XuIG9qH55poiv1sSHsVj0kQZgAAEOG55JtH10jzAcnfN/IeKDsAA0bDXRlD/+RCZY2W6qgzuEwJFuy41bHOr3lBqtF3wljjdiGiugXCMvcB8Llls7rIyC2NDP/d3FUQGm30gMxbtwA297y5gtWprBYLmvS9Vx0IsxoKgh9sKNw4JL86wWmoHLxh+SGvJgCGj8yV6WBwJB9or7W+iLUC1yE/5ZFckoPLIiPmV4/Neje9RzjKUHolyoQDWf71Cb2G1MxiNb/uwKaK91Gc4QwgNW3NRydO+AugK6HfUOxsredAGvmJGOGN0oMpclUUcPs0S3ywZGFyzX7VdpqvBXlrfb1rKZOqFvh8LgNW4/EWgdksq8ZYZcPT9balKGwYFePWsh8k2bk9R5dFaAlk/yEW+DWrIHqOciHVvUToHAWtSABp8yNKlKTFZgN4AxPmvmXCDoG7oJNfPCG407i1Y4vOfMzDVEFRpLkqgewI2WqLgnphDTBr6CVhWi5YseakrnZxUx7ZEt3YRWDsZ3Ne660ouykxghuo9Fs7Vo/GSr/PQ4t4Tul00gRRNd8H/XT5HlHyw7pcG8aGfVsRP/AtIypXm/yEG0XeVwcKAaI/mKUhuhHZHmXmya5SG6ryKYWZPUoco3og/B3rPoF+LkuLuxcNcVktWfNipLxaCAoxJb9BcrGLUHNEr2rm1BfsPGSdmHm/20jgxxVnyN+UT8WXXOYaFbgAab6XSorqKOuLoWBeEPCkxIXm6+QZPOLa8WMWkbMPaPWbFDg1UxjWd2aaXPGw4EoDP6D8hKpl7a6CKNDwMGAKE/YcdR22CYjsnn+rIzJptJqGkxCppFIY2i8p62syiY3+vtvjliDMfQrfCcnrIUt4/aFpwkArbkgUhKC+XRbt2Cr9GK3kvOzu2PVGhu7iqUVaJ1RvdiZD5UdXAnPrG75P9p+6D0lIZ1RynKmskEzUQT9dMhH/H8TkZViqHvYvenykVO03KpBKIyBG0/LRIZEIKJZhl3L9CP53AA7iBL1wRNcE2Ny8206sy7g6KzgofERfyWRmdA+snTYZJCwqssHTHA2ix5C4QigD", "User-Agent": "Microsoft SkyDriveSync 25.199.1012.0002 ship; Windows NT 10.0 (26200)", "Application": "SkyDriveSync", "Prefer": "Include-Feature=Vault", "Scenario": "CheckForChanges_FindChangesOther_ODB_FindChangesScenario/NotificationLatencyScenario", "ScenarioType": "PO", "X-EnumerationReason": "65536", "X-GeoMoveOptions": "HttpRedirection", "X-MachineId": "ccb3b9f6-d887-40d5-808f-80eda35ef908", "X-RequestStats": "did=ee9e9f11-aa1d-a42f-2180-161c15db7adb;ftuc=1;btuc=107916;stid=03de5f6c-ece5-44bf-a06b-3cf65a984219;", "X-ResponseStructure": "Flat", "X-RestrictedWriteCapabilities": "Irm, LabelIrm, RequiredColumn", "X-SyncFeatures": "996a", "X-SyncOptions": "HierarchicalKnowledge", "X-TransactionId": "77c3ba08-6653-4b94-b6b6-d802e1415fb5FindChangesOther", "X-UpdateGroupId": "100", "X-UpdateRing": "Prod", "Host": "201667-ipv4fdsmte.gr.global.aa-rt.sharepoint.com"}, "body_is_text": true, "body": ""}, "response": {"status_code": 200, "reason": "OK", "http_version": "HTTP/1.1", "headers": {"Cache-Control": "private, max-age=0", "Content-Length": "2539", "Content-Type": "Application/Web3s+xml", "Expires": "Thu, 23 Oct 2025 21:07:00 GMT", "Last-Modified": "Fri, 07 Nov 2025 22:07:00 GMT", "Vary": "Origin", "Server": "Microsoft-IIS/10.0", "IsOCDI": "0", "X-NetworkStatistics": "0,4195100,0,0,22916,50003,50003,282868", "X-SharePointHealthScore": "3", "X-SP-SERVERSTATE": "ReadOnly=0", "X-SyncStatus": "IncrementalChanges", "X-QuotaState": "Normal", "X-ListLevelQuotaState": "Normal", "X-LastProcessedChange": "1;3;5d2445a6-f48d-4f6c-b190-640d11e29a93;638981500204270000;832324008", "X-SyncToken": "4;%234;%231;3;5d2445a6-f48d-4f6c-b190-640d11e29a93;638981500204270000;832324008;%23;%23;%230;%23", "X-ResponseStructure": "Flat", "X-EnvironmentId": "4", "SPClientServiceRequestDuration": "44", "X-AspNet-Version": "4.0.30319", "X-DataBoundary": "NONE", "X-1DSCollectorUrl": "https://mobile.events.data.microsoft.com/OneCollector/1.0/", "X-AriaCollectorURL": "https://browser.pipe.aria.microsoft.com/Collector/3.0/", "X-FarmName": "US_543_BL21_201667_Content", "SPRequestGuid": "8a28d7a1-e070-0000-1405-2b5592c8dee2", "request-id": "8a28d7a1-e070-0000-1405-2b5592c8dee2", "MS-CV": "odcoinDgAAAUBStVksje4g.0", "SPLogId": "8a28d7a1-e070-0000-1405-2b5592c8dee2", "Alt-Svc": "h3=\":443\";ma=86400", "X-ResponseStats": "ViaAFD=False;", "Strict-Transport-Security": "max-age=31536000", "X-FRAME-OPTIONS": "SAMEORIGIN", "Content-Security-Policy": "frame-ancestors 'self' teams.microsoft.com *.teams.microsoft.com *.skype.com *.teams.microsoft.us local.teams.office.com teams.cloud.microsoft teams.live.com *.teams.live.com *.office365.com goals.cloud.microsoft *.powerapps.com *.powerbi.com *.yammer.com engage.cloud.microsoft word.cloud.microsoft excel.cloud.microsoft powerpoint.cloud.microsoft *.officeapps.live.com *.office.com *.microsoft365.com m365.cloud.microsoft *.cloud.microsoft *.stream.azure-test.net *.dynamics.com *.microsoft.com onedrive.live.com *.onedrive.live.com securebroker.sharepointonline.com;", "X-Powered-By": "ASP.NET", "MicrosoftSharePointTeamServices": "16.0.0.26622", "X-Content-Type-Options": "nosniff", "X-MS-InvokeApp": "1; RequireReadOnly", "P3P": "CP=\"ALL IND DSP COR ADM CONo CUR CUSo IVAo IVDo PSA PSD TAI TELo OUR SAMo CNT COM INT NAV ONL PHY PRE PUR UNI\"", "Date": "Fri, 07 Nov 2025 22:07:00 GMT"}, "body_is_text": true, "body": "﻿<?xml version=\"1.0\" encoding=\"utf-8\"?><Folder><ItemType>Folder</ItemType><ResourceID>f0ce10dfa5334200b28631f7d2066eab</ResourceID><ETag>f0ce10dfa5334200b28631f7d2066eab</ETag><DateCreated>2025-01-09T16:02:17.0000000Z</DateCreated><DateModified>2025-11-07T22:07:00.0000000Z</DateModified><RelationshipName>RootFolder</RelationshipName><Path>/RootFolder</Path><ParentResourceID>5d2445a6f48d4f6cb190640d11e29a93</ParentResourceID><Items><Document><ItemType>Document</ItemType><ResourceID>22163376c9e14541a103b8c1d74daf5f</ResourceID><ETag>\"{22163376-C9E1-4541-A103-B8C1D74DAF5F},5\"</ETag><DateCreated>2025-11-07T22:06:48.0000000Z</DateCreated><DateModified>2025-11-07T22:06:58.0000000Z</DateModified><RelationshipName>mitm-2025-11-08.jsonl</RelationshipName><Path>/RootFolder/Desktop/ants/mitm_logs/mitm-2025-11-08.jsonl</Path><ParentResourceID>a7b4e912f5694580aca3e399f60a3ba4</ParentResourceID><fsshttpstate.xschema.storage.live.com><Hash>/oskzxlIPFj9i0OLNIKyupgbvkE=</Hash><VersionToken>KgnhZnsBN0y8qh354QbmegUkAAMFRACKCAAA</VersionToken></fsshttpstate.xschema.storage.live.com><DocumentStreams><DocumentStream><DocumentStreamName>Binary</DocumentStreamName><DataSize>1286491</DataSize><PreAuthURL>https://my.microsoftpersonalcontent.com/personal/FB0E114B901691BD/_layouts/15/download.aspx?UniqueId=%7B22163376%2Dc9e1%2D4541%2Da103%2Db8c1d74daf5f%7D&amp;UserAgent=SkySync</PreAuthURL><XORHash>/oskzxlIPFj9i0OLNIKyupgbvkE=</XORHash><WriteValidationToken>/oskzxlIPFj9i0OLNIKyupgbvkE=</WriteValidationToken><StreamSyncToken>djMWIuHJQUWhA7jB102vXyICAAAAAAAA</StreamSyncToken><StreamProtocolSupport>4</StreamProtocolSupport></DocumentStream></DocumentStreams><LabelHash /><LabelHashScope>1</LabelHashScope><IsLabelProtected>False</IsLabelProtected><SubstrateFileId>SPO_Y2U5ZDY2ZWEtZmJjMS00NGIwLWEzZGUtYTk1ODQ1OTQ5Nzk5LDQ2Yzg0ZTNmLTRkYTctNDRhNC05NTIwLTE0NmRhM2MyNjI1Nyw1ZDI0NDVhNi1mNDhkLTRmNmMtYjE5MC02NDBkMTFlMjlhOTM_01OK5CVS3WGMLCFYOJIFC2CA5YYHLU3L27</SubstrateFileId><CreatedBy>Nishant Mohan</CreatedBy><LastModifiedBy>Nishant Mohan</LastModifiedBy><ModifierIdentity><CustomIdentity><Name>SkyDriveSync</Name><Value>078602e5-31f1-41fc-a168-ffff0c000000</Value></CustomIdentity></ModifierIdentity><ChangeTime>2025-11-07T22:07:01.0000000Z</ChangeTime></Document></Items><QuotaState>Normal</QuotaState><SpaceUsed>1844259792</SpaceUsed><SpaceGranted>27487790694400</SpaceGranted><ListLevelQuotaState>Normal</ListLevelQuotaState><ListLevelSpaceUsed>718439971</ListLevelSpaceUsed><ListLevelSpaceGranted>5368709120</ListLevelSpaceGranted></Folder>"}, "timings": {"request_start": 1762553221.000268, "request_end": 1762553221.000268, "response_start": 1762553221.3485036, "response_end": 1762553221.3645003}, "flow_id": "72459341-82d5-42f2-a85a-34aad85af2c7"}

# response(flow)
```

## Development Notes

### Key Features Evolution:
1. **Basic filtering**: Only log flows matching security rules
2. **Enhanced analysis**: Added comprehensive security indicators
3. **LLM integration**: Automatic analysis of flagged traffic
4. **Multi-file output**: Separate files for summaries, alerts, and raw data

### Security Indicators:
- **Sensitive Headers**: Authorization, Cookie, X-Api-Key, Client-Id
- **Attack Vectors**: Common injection parameters (q, id, data, callback, redirect_to, cmd)
- **Content Analysis**: Unusual content types, suspicious query parameters
- **Size Monitoring**: Large requests/responses for exfiltration detection

### File Structure:
- `summary-{date}.jsonl`: All flow summaries
- `alerts-{date}.jsonl`: LLM-analyzed flagged traffic  
- `full-{date}.jsonl`: Complete raw flows for flagged traffic
