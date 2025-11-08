import os
import json
import openai
from typing import Dict, Any
from .base_analyzer import BaseAnalyzer

class OpenAIAnalyzer(BaseAnalyzer):
    """Security analyzer using OpenAI's models."""
    
    def __init__(self, model_name: str = "gpt-4o"):
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY not found in environment variables")
        
        self.client = openai.OpenAI(api_key=api_key)
        self.model_name = model_name
        
    def analyze_content(self, content: str) -> Dict[str, Any]:
        """Analyze content using OpenAI model."""
        try:
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": "You are a security analyst. Analyze the HTTP traffic and respond in JSON format with: {\"severity\": number, \"tags\": string[], \"decision\": \"allow|alert|redact|block\", \"reason\": string}."},
                    {"role": "user", "content": content}
                ],
                temperature=0.3,
                max_tokens=1024
            )
            
            if not response.choices or not response.choices[0].message.content:
                return self._error_response("No response from model")
                
            try:
                return json.loads(response.choices[0].message.content)
            except json.JSONDecodeError:
                return self._error_response(f"Invalid response format: {response.choices[0].message.content[:200]}...")
                
        except Exception as e:
            return self._error_response(f"Analysis error: {str(e)}")
    
    def get_model_name(self) -> str:
        return f"OpenAI {self.model_name}"
    
    def _error_response(self, reason: str) -> Dict[str, Any]:
        return {
            "severity": 0,
            "tags": ["analysis_error"],
            "decision": "alert",
            "reason": reason
        }
