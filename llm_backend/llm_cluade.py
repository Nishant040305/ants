import os
import json
from anthropic import Anthropic, APIError

# --- Configuration ---
# Claude's API key should be set as an environment variable for security
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
KEY = "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"
if not ANTHROPIC_API_KEY:
    raise ValueError("ANTHROPIC_API_KEY environment variable not set.")

# Initialize the Anthropic client
try:
    client = Anthropic(api_key=ANTHROPIC_API_KEY)
except Exception as e:
    print(f"Error initializing Anthropic client: {e}")
    raise

# Recommended Claude model for fast, reliable JSON output
MODEL_NAME = "claude-3-haiku-20240307"

# --- Prompt Definition (Optimized for JSON output) ---

# The system prompt is crucial for Claude to enforce its persona and output format.
SYSTEM_PROMPT = """
You are a highly skilled cybersecurity network analyst. Your sole task is to analyze the provided HTTP flow summary.
Your entire response MUST be a single, valid JSON object. Do not include any introductory text, explanations, or markdown fences (like ```json).
You MUST strictly adhere to the provided output schema and action list.
"""

# The user prompt contains the data and the desired schema.
PROMPT_USER = """
Analyze the following Flow Summary:
{payload}

Return JSON only, adhering strictly to the following schema:
{{
  "llm_risk_level": "low|medium|high|critical",
  "llm_explanation": "A concise, contextual summary of the risk and traffic findings.",
  "llm_recommended_action": "One of the following: ALLOW, BLOCK, REJECT, LOG, WARN, or ALERT."
}}
"""

# --- Analysis Function ---

def analyze(summary: dict) -> dict:
    """
    Analyzes a security-focused flow summary using the Claude LLM 
    and returns a structured JSON analysis.
    """
    try:
        # Format the user prompt with the flow data
        text = PROMPT_USER.format(payload=json.dumps(summary, ensure_ascii=False, indent=2))
        
        # Call the Anthropic API
        response = client.messages.create(
            model=MODEL_NAME,
            system=SYSTEM_PROMPT,  # Use the system prompt to enforce rules
            messages=[{"role": "user", "content": text}],
            temperature=0.2, # Low temperature for factual analysis
            max_tokens=2048
        )
        
        # Claude returns a list of content blocks; we expect the first to be the JSON string
        content = response.content[0].text.strip()
        
        # Parse the JSON string into a Python dictionary
        return json.loads(content)
        
    except APIError as e:
        print(f"Claude API Error: {e.status_code} - {e.response.text}")
        return {"llm_risk_level": "critical", "llm_explanation": f"Claude API call failed: {e.status_code}", "llm_recommended_action": "ALERT"}
    except json.JSONDecodeError:
        print(f"JSON Decoding Error: Model output was not valid JSON. Raw Output: {content}")
        return {"llm_risk_level": "critical", "llm_explanation": "Model failed to return valid JSON output.", "llm_recommended_action": "ALERT"}
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return {"llm_risk_level": "critical", "llm_explanation": f"Unexpected error: {e}", "llm_recommended_action": "ALERT"}

# --- Example Usage ---
if __name__ == "__main__":
    print("--- Running Claude Analysis Test ---")
    
    # Example summary data (replace with your actual packet summary)
    test_flow_summary = {
        "host": "malicious-domain.xyz",
        "path": "/api/upload",
        "method": "POST",
        "req_content_length": 520000, 
        "resp_content_length": 100,
        "has_sensitive_header": True,
        "tags": ["large_upload", "untrusted_domain"],
        "user_agent": "Python/3.11 requests/2.28.1",
        "status_code": 200
    }

    if ANTHROPIC_API_KEY:
        analysis_result = analyze(test_flow_summary)
        print("\n✅ Claude Analysis Result:")
        print(json.dumps(analysis_result, indent=2))
    else:
        print("\n❌ Skipped analysis: Please set the ANTHROPIC_API_KEY environment variable to run the test.")