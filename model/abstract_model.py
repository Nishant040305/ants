import os
import json
import time
import requests
from typing import Optional, Dict, Any
from pathlib import Path
from dotenv import load_dotenv

class LLMModel:
    """
    A class to handle LLM interactions through OpenRouter
    """
    def __init__(self, api_key: Optional[str] = None):
        load_dotenv()  # Load environment variables from .env file if present
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY")
        if not self.api_key:
            raise ValueError("OpenRouter API key must be provided or set in OPENROUTER_API_KEY environment variable")
        
        self.base_url = "https://openrouter.ai/api/v1"
        self.default_model = "deepseek/deepseek-chat-v3.1:free"  # Default model
        self.max_retries = 3
        self.retry_delay = 1  # seconds
        
    def _load_prompt_template(self, prompt_file_path: str) -> Dict[str, Any]:
        """Load prompt template from a JSON file"""
        try:
            with open(prompt_file_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {
                "system": "You are a helpful AI assistant.",
                "format": "{content}"
            }
            
    def _prepare_messages(self, content: str, prompt_template: Dict[str, Any]) -> list:
        """Prepare messages array for the API request"""
        messages = []
        
        # Add system message if present
        if "system" in prompt_template:
            messages.append({
                "role": "system",
                "content": prompt_template["system"]
            })
            
        # Format user message
        user_content = prompt_template.get("format", "{content}").format(content=content)
        messages.append({
            "role": "user",
            "content": user_content
        })
        
        return messages
    
    def _make_request(self, messages: list, model_name: str) -> Dict[str, Any]:
        """Make the actual API request to OpenRouter"""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "HTTP-Referer": "https://github.com/Nishant040305/ants",  # Your project URL
            "Content-Type": "application/json"
        }
        
        data = {
            "model": model_name,
            "messages": messages
        }
        
        for attempt in range(self.max_retries):
            try:
                response = requests.post(
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    json=data,
                    timeout=30
                )
                response.raise_for_status()
                return response.json()
            
            except requests.RequestException as e:
                if attempt == self.max_retries - 1:
                    raise Exception(f"Failed to get response from OpenRouter after {self.max_retries} attempts: {str(e)}")
                time.sleep(self.retry_delay * (attempt + 1))
                
    def get_response(self, content: str, prompt_file_path: str = "", model_name: str = "") -> Dict[str, Any]:
        """
        Get a response from the LLM
        
        Args:
            content (str): The main content/query to send to the LLM
            prompt_file_path (str): Path to a JSON file containing prompt template
            model_name (str): Name of the model to use (defaults to google/gemma-7b)
            
        Returns:
            Dict containing the response and metadata
        """
        # Load prompt template
        prompt_template = self._load_prompt_template(prompt_file_path) if prompt_file_path else {}
        
        # Prepare messages
        messages = self._prepare_messages(content, prompt_template)
        
        # Make request
        response = self._make_request(messages, model_name or self.default_model)
        
        # Extract and return relevant information
        result = {
            "content": response["choices"][0]["message"]["content"],
            "model": response["model"],
            "usage": response.get("usage", {}),
            "metadata": {
                "prompt_template": prompt_template,
                "timestamp": time.time()
            }
        }
        
        return result