import os
import json
import requests
from typing import Dict, Any
from .base_analyzer import BaseAnalyzer

class GrokLlamaAnalyzer(BaseAnalyzer):
    """Security analyzer using Grok's LLaMA 3.1 model via API."""
    
    def __init__(self, model_name: str = "grok-llama-3.1-8b-instant"):
        self.api_key = os.getenv("GROK_API_KEY")
        if not self.api_key:
            raise ValueError("GROK_API_KEY not found in environment variables")
        
        self.model_name = model_name
        self.api_url = "https://api.x.ai/v1/chat/completions"  # Grok API endpoint
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
    def analyze_content(self, content: str) -> Dict[str, Any]:
        """Analyze content using Grok's LLaMA model."""
        try:
            prompt = f"""Analyze this HTTP traffic for security issues and respond in JSON format with: 
            {{"severity": number, "tags": string[], "decision": "allow|alert|redact|block", "reason": string}}
            
            Focus on:
            - SQL injection attempts
            - XSS payloads
            - Authentication bypasses
            - Data exfiltration patterns
            - Suspicious user agents
            - Command injection
            
            HTTP Traffic Data:
            {content}"""
            
            payload = {
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a cybersecurity expert analyzing HTTP traffic for threats. Always respond with valid JSON containing severity (0-10), tags (array), decision (allow/alert/redact/block), and reason (string)."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                "model": self.model_name,
                "temperature": 0.3,
                "max_tokens": 1024,
                "top_p": 0.8
            }
            
            response = requests.post(
                self.api_url,
                headers=self.headers,
                json=payload,
                timeout=30
            )
            
            if response.status_code != 200:
                return self._error_response(f"API error: {response.status_code} - {response.text}")
            
            response_data = response.json()
            
            if not response_data.get("choices"):
                return self._error_response("No response choices from model")
            
            content_text = response_data["choices"][0]["message"]["content"]
            
            if not content_text:
                return self._error_response("Empty response from model")
                
            try:
                # Parse JSON response
                result = json.loads(content_text)
                
                # Validate required fields
                if not all(key in result for key in ["severity", "tags", "decision", "reason"]):
                    return self._error_response("Missing required fields in response")
                
                return result
                
            except json.JSONDecodeError:
                return self._error_response(f"Invalid JSON response: {content_text[:200]}...")
                
        except requests.exceptions.RequestException as e:
            return self._error_response(f"Network error: {str(e)}")
        except Exception as e:
            return self._error_response(f"Analysis error: {str(e)}")
    
    def get_model_name(self) -> str:
        return f"Grok {self.model_name}"
    
    def _error_response(self, reason: str) -> Dict[str, Any]:
        return {
            "severity": 0,
            "tags": ["analysis_error"],
            "decision": "alert",
            "reason": reason
        }