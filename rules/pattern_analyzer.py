"""
Pattern-based analysis and detection rules
"""

import re
import json
from typing import Dict, Any


class PatternAnalyzer:
    def __init__(self):
        # Token pattern matching
        self.TOKEN_RE = re.compile(r'(sk-[A-Za-z0-9-_]{16,}|[A-Za-z0-9_]{24}\.[A-Za-z0-9_]{6}\.[A-Za-z0-9_-]{27}|[\w-]{24}\.[\w-]{6}\.[\w-]{27})')
        self.APIKEY_RE = re.compile(r'(AKIA[0-9A-Z]{16})|([A-Za-z0-9]{32,})')
        
        # Configuration thresholds
        self.ALERT_THRESHOLD = 6
        self.REDACT_THRESHOLD = 8
        self.BLOCK_THRESHOLD = 10
        
    def analyze_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Simple heuristic analyzer for HTTP payloads
        Returns severity score, tags, and decision
        """
        body = payload.get("body", "")
        headers = payload.get("headers", {})
        tags = []
        severity = 0
        
        # Check for tokens in body
        if self.TOKEN_RE.search(str(body)):
            tags.append("token_in_message")
            severity += 8
        
        # Check for tokens in headers
        auth_header = headers.get("authorization", "")
        if self.TOKEN_RE.search(str(auth_header)):
            tags.append("token_in_header")
            severity += 6
        
        # Check for API keys
        if self.APIKEY_RE.search(str(body)):
            tags.append("api_key_pattern")
            severity += 5
        
        # Check for emails
        if re.search(r'[\w\.-]+@[\w\.-]+', str(body)):
            tags.append("email_in_message")
            severity += 2
        
        # Clamp severity
        severity = min(max(severity, 0), 10)
        
        # Determine decision
        if severity >= self.BLOCK_THRESHOLD:
            decision = "block"
        elif severity >= self.REDACT_THRESHOLD:
            decision = "redact"
        elif severity >= self.ALERT_THRESHOLD:
            decision = "alert"
        else:
            decision = "allow"
        
        reason = f"Found {len(tags)} potential issues. Severity: {severity}"
        
        return {
            "severity": severity,
            "tags": tags,
            "decision": decision,
            "reason": reason,
            "explain": f"Analysis found {', '.join(tags)} with severity {severity}"
        }
    
    def redact_text(self, text: str, tags: list) -> str:
        """Redact sensitive information from text based on tags"""
        text = self.TOKEN_RE.sub("[REDACTED_TOKEN]", text)
        text = self.APIKEY_RE.sub("[REDACTED_KEY]", text)
        if "email_in_message" in tags or "email_sensitive" in tags:
            text = re.sub(r'[\w\.-]+@[\w\.-]+', "[REDACTED_EMAIL]", text)
        return text


if __name__ == "__main__":
    """Unit tests with sample data"""
    print("🧪 Testing PatternAnalyzer...")
    
    analyzer = PatternAnalyzer()
    
    # Test cases
    test_cases = [
        {
            "name": "Clean request",
            "payload": {
                "body": '{"message": "Hello world"}',
                "headers": {"content-type": "application/json"}
            }
        },
        {
            "name": "API key in body",
            "payload": {
                "body": '{"api_key": "sk-1234567890abcdef1234", "data": "test"}',
                "headers": {"content-type": "application/json"}
            }
        },
        {
            "name": "Token in Authorization header",
            "payload": {
                "body": '{"message": "test"}',
                "headers": {
                    "authorization": "Bearer sk-1234567890abcdef1234",
                    "content-type": "application/json"
                }
            }
        },
        {
            "name": "AWS credentials",
            "payload": {
                "body": '{"aws_access_key": "AKIAXXXXXXXXXXXXXXXX", "aws_secret": "abcdefghijklmnopqrstuvwxyz123456"}',
                "headers": {"content-type": "application/json"}
            }
        },
        {
            "name": "Email in message",
            "payload": {
                "body": '{"email": "user@example.com", "message": "Contact me"}',
                "headers": {"content-type": "application/json"}
            }
        },
        {
            "name": "Multiple issues",
            "payload": {
                "body": '{"api_key": "sk-1234567890abcdef1234", "email": "admin@company.com", "aws_key": "AKIAXXXXXXXXXXXXXXXX"}',
                "headers": {
                    "authorization": "Bearer sk-9876543210fedcba9876",
                    "content-type": "application/json"
                }
            }
        }
    ]
    
    print(f"\nRunning {len(test_cases)} test cases...\n")
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"Test {i}: {test_case['name']}")
        result = analyzer.analyze_payload(test_case['payload'])
        
        print(f"  Severity: {result['severity']}/10")
        print(f"  Decision: {result['decision']}")
        print(f"  Tags: {result['tags']}")
        print(f"  Reason: {result['reason']}")
        
        # Test redaction
        if result['tags']:
            sample_text = str(test_case['payload']['body'])
            redacted = analyzer.redact_text(sample_text, result['tags'])
            if redacted != sample_text:
                print(f"  Original: {sample_text}")
                print(f"  Redacted: {redacted}")
        
        print("-" * 50)
    
    print("✅ PatternAnalyzer tests completed!")