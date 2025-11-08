import os
import json
import google.generativeai as genai
from typing import Dict, Any
from .base_analyzer import BaseAnalyzer

class GeminiAnalyzer(BaseAnalyzer):
    """Security analyzer using Google's Gemini model."""
    
    def __init__(self, model_name: str = "gemini-1.5-flash"):
        api_key = os.getenv("GOOGLE_API_KEY")
        if not api_key:
            raise ValueError("GOOGLE_API_KEY not found in environment variables")
        
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel(model_name)
        self.model_name = model_name
        
    def analyze_content(self, content: str) -> Dict[str, Any]:
        """Analyze content using Gemini model."""
        try:
            prompt = f"""Analyze this HTTP traffic for security issues and respond in JSON format with: 
            {{"severity": number, "tags": string[], "decision": "allow|alert|redact|block", "reason": string}}
            
            {content}"""
            
            response = self.model.generate_content(
                prompt,
                generation_config={
                    "temperature": 0.3,
                    "top_p": 0.8,
                    "top_k": 40,
                    "max_output_tokens": 1024,
                }
            )
            
            if not response.text:
                return self._error_response("No response from model")
                
            try:
                return json.loads(response.text)
            except json.JSONDecodeError:
                return self._error_response(f"Invalid response format: {response.text[:200]}...")
                
        except Exception as e:
            return self._error_response(f"Analysis error: {str(e)}")
    
    def get_model_name(self) -> str:
        return f"Gemini {self.model_name}"
    
    def _error_response(self, reason: str) -> Dict[str, Any]:
        return {
            "severity": 0,
            "tags": ["analysis_error"],
            "decision": "alert",
            "reason": reason
        }
