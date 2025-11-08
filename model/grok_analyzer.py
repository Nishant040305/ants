import os
import json
import time
import requests
from typing import Dict, Any, Optional
from .base_analyzer import BaseAnalyzer


class GrokLlamaAnalyzer(BaseAnalyzer):
    """
    Security analyzer for 'llama-3.1-8b-instant' (Groq-hosted) models.

    Compatible with Groq's OpenAI-style Chat Completions API:
      https://api.groq.com/openai/v1/chat/completions

    Environment variables required:
      - GROK_API_URL   e.g. https://api.groq.com/openai/v1/chat/completions
      - GROK_API_KEY   your Groq API key (Bearer token)
    """

    def __init__(self, model_name: str = "llama-3.1-8b-instant"):
        self.model_name = model_name
        self.api_url = os.getenv("GROK_API_URL")
        self.api_key = os.getenv("GROK_API_KEY")

        if not self.api_url:
            raise ValueError("GROK_API_URL not found in environment variables")
        if not self.api_key:
            raise ValueError("GROK_API_KEY not found in environment variables")

        self._timeout = int(os.getenv("GROK_REQUEST_TIMEOUT", "30"))
        self._max_retries = int(os.getenv("GROK_MAX_RETRIES", "3"))

    def analyze_content(
        self, content: str, max_tokens: int = 1024, temperature: float = 0.3
    ) -> Dict[str, Any]:
        """
        Send content to Groq's chat completion endpoint and return parsed JSON analysis:
          {"severity": number, "tags": [...], "decision": "allow|alert|redact|block", "reason": "..."}
        """

        # 🧩 1. Truncate overly large payloads (prevent 413)
        if len(content) > 8000:
            content = content[:8000] + "\n[Truncated for analysis due to token limit]"

        system_prompt = (
            "You are a security analyst. Analyze the HTTP traffic below and respond ONLY in valid JSON "
            "with the following keys: {\"severity\": number, \"tags\": string[], "
            "\"decision\": \"allow|alert|redact|block\", \"reason\": string}. "
            "Do not include markdown formatting, backticks, or explanations."
        )

        payload = {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": content},
            ],
            "max_tokens": max_tokens,
            "temperature": temperature,
        }

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        # 🧠 2. Retry for 429 "rate limit reached"
        for attempt in range(self._max_retries):
            try:
                resp = requests.post(
                    self.api_url, json=payload, headers=headers, timeout=self._timeout
                )
            except Exception as e:
                return self._error_response(
                    f"Request error communicating with GROK endpoint: {str(e)}"
                )

            if resp.status_code == 429:
                wait_time = 10 * (attempt + 1)
                time.sleep(wait_time)
                continue  # retry again
            elif resp.status_code >= 400:
                return self._error_response(
                    f"GROK endpoint returned HTTP {resp.status_code}: {resp.text[:300]}"
                )

            break  # success, exit retry loop
        else:
            return self._error_response("Max retries exceeded for rate-limited request")

        # 🧩 3. Parse response
        try:
            j = resp.json()
        except Exception:
            text = resp.text.strip()
            try:
                return json.loads(text)
            except Exception:
                return self._error_response(
                    f"Invalid JSON response from GROK: {text[:500]}"
                )

        # 🧠 4. Handle OpenAI-style "choices" output
        if "choices" in j and isinstance(j["choices"], list) and j["choices"]:
            choice = j["choices"][0]
            text = None
            finish_reason = choice.get("finish_reason")

            if "message" in choice and isinstance(choice["message"], dict):
                text = choice["message"].get("content")
            elif "text" in choice:
                text = choice["text"]

            if text:
                # 🧹 Clean up Markdown JSON output
                cleaned = text.strip()
                if cleaned.startswith("```"):
                    cleaned = cleaned.strip("`")
                    if cleaned.lower().startswith("json"):
                        cleaned = cleaned[4:].strip()

                try:
                    return json.loads(cleaned)
                except json.JSONDecodeError:
                    return self._error_response(
                        f"Could not parse model text as JSON: {cleaned[:400]}",
                        finish_reason,
                    )

        # 🪶 5. Fallback
        return self._error_response(
            f"Unrecognized response shape from GROK endpoint: {json.dumps(j)[:800]}"
        )

    def get_model_name(self) -> str:
        return f"GrokLlama {self.model_name}"

    def _error_response(
        self, reason: str, finish_reason: Optional[Any] = None
    ) -> Dict[str, Any]:
        details = reason
        if finish_reason is not None:
            details = f"{details} (finish_reason={finish_reason})"
        return {
            "severity": 0,
            "tags": ["analysis_error"],
            "decision": "alert",
            "reason": details,
        }
