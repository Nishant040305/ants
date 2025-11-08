import os
import json
import anthropic
from typing import Dict, Any
from .base_analyzer import BaseAnalyzer

class ClaudeAnalyzer(BaseAnalyzer):
    """Security analyzer using Anthropic's Claude model."""
    
    def __init__(self, model_name: str = "claude-3-sonnet-20240229"):
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY not found in environment variables")
        
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model_name = model_name
        
    def analyze_content(self, content: str) -> Dict[str, Any]:
        """Analyze content using Claude model."""
        try:
            message = self.client.messages.create(
                model=self.model_name,
                max_tokens=1024,
                temperature=0.3,
                system="You are a security analyst. Analyze the HTTP traffic and respond in JSON format with: {\"severity\": number, \"tags\": string[], \"decision\": \"allow|alert|redact|block\", \"reason\": string}.",
                messages=[
                    {"role": "user", "content": content}
                ]
            )
            
            if not message.content:
                return self._error_response("No response from model")
                
            try:
                # Extract text from the content block
                response_text = message.content[0].text
                return json.loads(response_text)
            except (json.JSONDecodeError, IndexError, AttributeError):
                return self._error_response(f"Invalid response format: {str(message.content)[:200]}...")
                
        except Exception as e:
            return self._error_response(f"Analysis error: {str(e)}")
    
    def get_model_name(self) -> str:
        return f"Claude {self.model_name}"
    
    def _error_response(self, reason: str) -> Dict[str, Any]:
        return {
            "severity": 0,
            "tags": ["analysis_error"],
            "decision": "alert",
            "reason": reason
        }
