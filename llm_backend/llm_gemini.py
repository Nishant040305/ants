# # # # # import google.generativeai as genai
# # # # # import json
# # # # # import os

# # # # # # Set API Key:
# # # # # # export GEMINI_API_KEY="your-key"
# # # # # genai.configure(api_key=os.getenv("AIzaSyDei4mmgH9j_siUgUghKucxa0wgKhd_prQ"))

# # # # # model = genai.GenerativeModel("gemini-pro")
# # # # # curl "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent" \
# # # # #   -H 'Content-Type: application/json' \
# # # # #   -H 'X-goog-api-key: AIzaSyDei4mmgH9j_siUgUghKucxa0wgKhd_prQ' \
# # # # #   -X POST \
# # # # #   -d '{
# # # # #     "contents": [
# # # # #       {
# # # # #         "parts": [
# # # # #           {
# # # # #             "text": "Explain how AI works in a few words"
# # # # #           }
# # # # #         ]
# # # # #       }
# # # # #     ]
# # # # #   }'
# # # # # PROMPT = """
# # # # # You are a cybersecurity network analyst.
# # # # # Analyze this HTTP flow summary:

# # # # # {payload}

# # # # # Return JSON only:
# # # # # {{
# # # # #   "risk_level": "low|medium|high",
# # # # #   "explanation": "...",
# # # # #   "recommended_action": "..."
# # # # # }}
# # # # # """

# # # # # def analyze(summary: dict) -> dict:
# # # # #     text = PROMPT.format(payload=json.dumps(summary, ensure_ascii=False))
# # # # #     response = model.generate_content(text)
# # # # #     cleaned = response.text.strip().replace("```json","").replace("```","")
# # # # #     return json.loads(cleaned)

# # # # import google.generativeai as genai
# # # # import json
# # # # import os
# # # # from google.generativeai.errors import APIError

# # # # # --- 1. Configuration ---
# # # # # Use the correct environment variable name for the SDK (GEMINI_API_KEY)
# # # # # NOTE: The API key provided in the prompt is redacted/invalid. 
# # # # # A valid key must be set in your environment.
# # # # API_KEY = os.getenv("AIzaSyDei4mmgH9j_siUgUghKucxa0wgKhd_prQ") 
# # # # if not API_KEY:
# # # #     # A more secure and informative way to handle missing keys
# # # #     raise ValueError("GEMINI_API_KEY environment variable not set.")

# # # # try:
# # # #     genai.configure(api_key=API_KEY)
# # # # except Exception as e:
# # # #     print(f"Error configuring the SDK: {e}")
# # # #     # Exit or handle the error appropriately

# # # # # Use the recommended model for general tasks
# # # # MODEL_NAME = "gemini-2.5-flash" 
# # # # model = genai.GenerativeModel(MODEL_NAME)

# # # # # --- 2. Prompt Definition ---
# # # # PROMPT = """
# # # # You are a cybersecurity network analyst.
# # # # Analyze the following HTTP flow summary provided in JSON format.
# # # # Your response MUST be ONLY a single JSON object. Do not include any text, explanations, or markdown fences (like ```json).

# # # # FLOW SUMMARY:
# # # # {payload}

# # # # Return JSON only:
# # # # {
# # # #   "risk_level": "low|medium|high|critical",
# # # #   "explanation": "A concise summary of the analysis, focusing on potential threats or normalcy.",
# # # #   "recommended_action": "Specific action to be taken (e.g., 'Monitor', 'Block IP', 'Investigate User')"
# # # # }
# # # # """

# # # # # --- 3. Analysis Function ---
# # # # def analyze(summary: dict) -> dict:
# # # #     """
# # # #     Analyzes an HTTP flow summary using the Gemini API and returns a structured JSON analysis.
# # # #     """
# # # #     try:
# # # #         # Create the full prompt text
# # # #         text = PROMPT.format(payload=json.dumps(summary, ensure_ascii=False, indent=2))
        
# # # #         # Use system instructions for better adherence to the persona and output format
# # # #         # This is a key improvement for reliable JSON output.
# # # #         response = model.generate_content(
# # # #             contents=text,
# # # #             config=genai.types.GenerateContentConfig(
# # # #                 system_instruction="You are a cybersecurity network analyst. Your response MUST be ONLY a single JSON object that strictly adheres to the provided schema."
# # # #             )
# # # #         )
        
# # # #         # The model is instructed to return only JSON, minimizing the need for heavy cleanup.
# # # #         cleaned_text = response.text.strip()
        
# # # #         # Attempt to parse the JSON output
# # # #         return json.loads(cleaned_text)

# # # #     except APIError as e:
# # # #         print(f"Gemini API Error: {e}")
# # # #         # Return a fallback JSON for error states
# # # #         return {"risk_level": "critical", "explanation": f"API call failed: {e}", "recommended_action": "Check API status and logs."}
# # # #     except json.JSONDecodeError:
# # # #         print(f"JSON Decoding Error: Model output was not valid JSON.")
# # # #         print(f"Raw Model Output: {response.text}")
# # # #         # Return a fallback JSON for parsing errors
# # # #         return {"risk_level": "critical", "explanation": "Model failed to return valid JSON output.", "recommended_action": "Review prompt and model output for formatting errors."}
# # # #     except Exception as e:
# # # #         print(f"An unexpected error occurred: {e}")
# # # #         return {"risk_level": "critical", "explanation": f"Unexpected error during analysis: {e}", "recommended_action": "Review script logic."}

# # # # # --- Example Usage (Not part of the core function, but helpful for testing) ---
# # # # # if __name__ == "__main__":
# # # # #     sample_summary = {
# # # # #         "source_ip": "10.1.1.5",
# # # # #         "destination_ip": "153.19.12.87",
# # # # #         "port": 80,
# # # # #         "protocol": "TCP",
# # # # #         "payload_size": 250000,
# # # # #         "timestamp": "2025-11-08T11:00:00Z",
# # # # #         "metadata": "Large payload on HTTP port 80 (unencrypted). Suspicious."
# # # # #     }
# # # # #     
# # # # #     print("--- Running Analysis ---")
# # # # #     analysis_result = analyze(sample_summary)
# # # # #     print(json.dumps(analysis_result, indent=2))

# # # import google.generativeai as genai
# # # import json
# # # import os
# # # from google.api_core.exceptions import GoogleAPICallError

# # # # ⚠️ WARNING: Replacing this placeholder with your actual key hardcodes the secret! 
# # # # Use environment variables (os.getenv) for production code.
# # # # --- 1. Hardcoded API Key Configuration ---
# # # HARDCODED_API_KEY = "AIzaSyDei4mmgH9j_siUgUghKucxa0wgKhd_prQ"  # <-- REPLACE THIS PLACEHOLDER

# # # if HARDCODED_API_KEY == "YOUR_HARDCODED_API_KEY":
# # #     # Fallback to environment variable if the placeholder key is still set, 
# # #     # as a minor safety measure, or raise an error.
# # #     api_key_source = os.getenv("GEMINI_API_KEY")
# # #     if not api_key_source:
# # #         raise ValueError("API Key not set. Please replace 'YOUR_HARDCODED_API_KEY' or set the GEMINI_API_KEY environment variable.")
# # #     else:
# # #         API_KEY = api_key_source
# # # else:
# # #     API_KEY = HARDCODED_API_KEY

# # # try:
# # #     # Use the directly available key
# # #     genai.configure(api_key=API_KEY)
# # # except Exception as e:
# # #     print(f"Error configuring the SDK: {e}")
# # #     # Re-raise the exception after printing for critical failures
# # #     raise 

# # # MODEL_NAME = "gemini-2.5-flash"
# # # model = genai.GenerativeModel(MODEL_NAME)


# # # # --- LLM Prompt Definition ---
# # # PROMPT_LLM = """
# # # You are a cybersecurity network analyst.
# # # Analyze the following HTTP flow summary provided in JSON format.
# # # Your analysis must be contextual and consider multiple indicators.

# # # Your final recommended action MUST be one of the following: 
# # # "ALLOW", "BLOCK", "REJECT", "LOG", "WARN", or "ALERT".

# # # FLOW SUMMARY:
# # # {payload}

# # # Return JSON only:
# # # {{
# # #   "llm_risk_level": "low|medium|high|critical",
# # #   "llm_explanation": "A concise, contextual summary of the analysis and risk.",
# # #   "llm_recommended_action": "One of: ALLOW, BLOCK, REJECT, LOG, WARN, or ALERT."
# # # }}
# # # """

# # # # --- LLM Analysis Function ---
# # # def analyze(summary: dict) -> dict:
# # #     """
# # #     Analyzes a security-focused flow summary using the Gemini LLM 
# # #     and returns a structured JSON analysis with one of the defined actions.
# # #     """
# # #     try:
# # #         text = PROMPT_LLM.format(payload=json.dumps(summary, ensure_ascii=False, indent=2))
        
# # #         # The model object is already configured with the key
# # #         response = model.generate_content(
# # #             contents=text,
# # #             config=genai.types.GenerateContentConfig(
# # #                 # Enforce the persona and the specific output format/actions
# # #                 system_instruction="You are a cybersecurity network analyst. Your response MUST be ONLY a single JSON object that strictly adheres to the provided schema. The recommended action MUST be one of: ALLOW, BLOCK, REJECT, LOG, WARN, or ALERT."
# # #             )
# # #         )
        
# # #         cleaned_text = response.text.strip().replace("```json","").replace("```","")
# # #         return json.loads(cleaned_text)

# # #     except GoogleAPICallError as e:
# # #         print(f"Gemini API Error: {e}")
# # #         return {"llm_risk_level": "critical", "llm_explanation": f"API call failed: {e}", "llm_recommended_action": "ALERT"}
# # #     except json.JSONDecodeError:
# # #         print(f"JSON Decoding Error: Model output was not valid JSON.")
# # #         return {"llm_risk_level": "critical", "llm_explanation": "Model failed to return valid JSON output.", "llm_recommended_action": "ALERT"}
# # #     except Exception as e:
# # #         print(f"An unexpected error occurred: {e}")
# # #         return {"llm_risk_level": "critical", "llm_explanation": f"Unexpected error: {e}", "llm_recommended_action": "ALERT"}
    


# # import google.generativeai as genai
# # import json
# # import os
# # from google.api_core.exceptions import GoogleAPICallError

# # HARDCODED_API_KEY = "AIzaSyDei4mmgH9j_siUgUghKucxa0wgKhd_prQ"  # <-- REPLACE THIS PLACEHOLDER

# # try:
# #     # Use the directly available key
# #     genai.configure(api_key=HARDCODED_API_KEY)
# # except Exception as e:
# #     print(f"Error configuring the SDK: {e}")
# #     # Re-raise the exception after printing for critical failures
# #     raise 

# # MODEL_NAME = "gemini-2.5-flash"
# # model = genai.GenerativeModel(MODEL_NAME)


# # # --- LLM Prompt Definition ---
# # PROMPT_LLM = """
# # You are a highly skilled cybersecurity network analyst specializing in threat detection.
# # Analyze the following comprehensive HTTP flow context provided in JSON format.
# # Pay special attention to the 'tags' from the static rules, the 'request_host', 
# # the 'request_payload_snippet', and the 'response_payload_snippet' for encoded data, 
# # suspicious commands, or malicious strings. Use all available context.

# # Your final recommended action MUST be one of the following: 
# # "ALLOW", "BLOCK", "REJECT", "LOG", "WARN", or "ALERT".

# # FULL FLOW CONTEXT (including summary and payloads):
# # {payload}

# # Return JSON only:
# # {{
# #   "risk_level": "low|medium|high|critical",
# #   "llm_explanation": "A concise, contextual summary of the analysis and risk.",
# #   "llm_recommended_action": "One of: ALLOW, BLOCK, REJECT, LOG, WARN, or ALERT."
# # }}
# # """

# # # --- LLM Analysis Function ---
# # def analyze(llm_context: dict) -> dict:
# #     """
# #     Analyzes a security-focused flow summary and rich context using the Gemini LLM 
# #     and returns a structured JSON analysis with one of the defined actions.
    
# #     The input dictionary is expected to contain a 'summary' key (the static analysis 
# #     results) and other keys like 'request_host' and payload snippets.
# #     """
# #     try:
# #         # Use the entire context dictionary as the payload for the LLM
# #         text = PROMPT_LLM.format(payload=json.dumps(llm_context, ensure_ascii=False, indent=2))
        
# #         # The model object is already configured with the key
# #         response = model.generate_content(
# #             contents=text,
# #             config=genai.types.GenerateContentConfig(
# #                 # Enforce the persona and the specific output format/actions
# #                 system_instruction="You are a cybersecurity network analyst. Your response MUST be ONLY a single JSON object that strictly adheres to the provided schema. The recommended action MUST be one of: ALLOW, BLOCK, REJECT, LOG, WARN, or ALERT."
# #             )
# #         )
        
# #         cleaned_text = response.text.strip().replace("```json","").replace("```","")
# #         return json.loads(cleaned_text)

# #     except GoogleAPICallError as e:
# #         print(f"Gemini API Error: {e}")
# #         return {"risk_level": "critical", "llm_explanation": f"API call failed: {e}", "llm_recommended_action": "ALERT"}
# #     except json.JSONDecodeError:
# #         print(f"JSON Decoding Error: Model output was not valid JSON: {response.text[:100]}...")
# #         return {"risk_level": "critical", "llm_explanation": "Model failed to return valid JSON output.", "llm_recommended_action": "ALERT"}
# #     except Exception as e:
# #         print(f"An unexpected error occurred: {e}")
# #         return {"risk_level": "critical", "llm_explanation": f"Unexpected error: {e}", "llm_recommended_action": "ALERT"}


# import google.generativeai as genai
# import json
# import os
# from google.api_core.exceptions import GoogleAPICallError
# # Explicitly import GenerateContentConfig for robustness against different SDK versions
# from google.generativeai.types import GenerateContentConfig 


# # ⚠️ WARNING: Replacing this placeholder with your actual key hardcodes the secret! 
# # Use environment variables (os.getenv) for production code.
# # --- 1. Hardcoded API Key Configuration ---
# HARDCODED_API_KEY = "AIzaSyDei4mmgH9j_siUgUghKucxa0wgKhd_prQ"  # <-- REPLACE THIS PLACEHOLDER

# if HARDCODED_API_KEY == "YOUR_HARDCODED_API_KEY" or HARDCODED_API_KEY == "AIzaSyDei4mmgH9j_siUgUghKucxa0wgKhd_prQ":
#     # Fallback to environment variable if the placeholder key is still set, 
#     # as a minor safety measure, or raise an error.
#     api_key_source = os.getenv("GEMINI_API_KEY")
#     if not api_key_source:
#         # NOTE: Keeping the original placeholder key is a known issue in the provided template
#         # Reverting to the provided key if no env var is found to maintain functionality
#         API_KEY = HARDCODED_API_KEY
#         print("Warning: Using placeholder API key. Please set GEMINI_API_KEY environment variable.")
#     else:
#         API_KEY = api_key_source
# else:
#     API_KEY = HARDCODED_API_KEY

# try:
#     # Use the directly available key
#     genai.configure(api_key=API_KEY)
# except Exception as e:
#     print(f"Error configuring the SDK: {e}")
#     # Re-raise the exception after printing for critical failures
#     raise 

# MODEL_NAME = "gemini-2.5-flash"
# model = genai.GenerativeModel(MODEL_NAME)


# # --- LLM Prompt Definition ---
# PROMPT_LLM = """
# You are a highly skilled cybersecurity network analyst specializing in threat detection.
# Analyze the following comprehensive HTTP flow context provided in JSON format.
# Pay special attention to the 'tags' from the static rules, the 'request_host', 
# the 'request_payload_snippet', and the 'response_payload_snippet' for encoded data, 
# suspicious commands, or malicious strings. Use all available context.

# Your final recommended action MUST be one of the following: 
# "ALLOW", "BLOCK", "REJECT", "LOG", "WARN", or "ALERT".

# FULL FLOW CONTEXT (including summary and payloads):
# {payload}

# Return JSON only:
# {{
#   "risk_level": "low|medium|high|critical",
#   "explanation": "A concise, contextual summary of the analysis and risk.",
#   "recommended_action": "One of: ALLOW, BLOCK, REJECT, LOG, WARN, or ALERT."
# }}
# """

# # --- LLM Analysis Function ---
# def analyze(llm_context: dict) -> dict:
#     """
#     Analyzes a security-focused flow summary and rich context using the Gemini LLM 
#     and returns a structured JSON analysis with one of the defined actions.
    
#     The input dictionary is expected to contain a 'summary' key (the static analysis 
#     results) and other keys like 'request_host' and payload snippets.
#     """
#     try:
#         # Use the entire context dictionary as the payload for the LLM
#         text = PROMPT_LLM.format(payload=json.dumps(llm_context, ensure_ascii=False, indent=2))
        
#         # The model object is already configured with the key
#         response = model.generate_content(
#             contents=text,
#             config=GenerateContentConfig(  # Now using the explicitly imported class
#                 # Enforce the persona and the specific output format/actions
#                 system_instruction="You are a cybersecurity network analyst. Your response MUST be ONLY a single JSON object that strictly adheres to the provided schema. The recommended action MUST be one of: ALLOW, BLOCK, REJECT, LOG, WARN, or ALERT."
#             )
#         )
        
#         cleaned_text = response.text.strip().replace("```json","").replace("```","")
#         return json.loads(cleaned_text)

#     except GoogleAPICallError as e:
#         print(f"Gemini API Error: {e}")
#         # Ensure consistent keys are used here
#         return {"risk_level": "critical", "explanation": f"API call failed: {e}", "recommended_action": "ALERT"}
#     except json.JSONDecodeError:
#         print(f"JSON Decoding Error: Model output was not valid JSON: {response.text[:100]}...")
#         # Ensure consistent keys are used here
#         return {"risk_level": "critical", "explanation": "Model failed to return valid JSON output.", "recommended_action": "ALERT"}
#     except Exception as e:
#         print(f"An unexpected error occurred: {e}")
#         # Ensure consistent keys are used here
#         return {"risk_level": "critical", "explanation": f"Unexpected error: {e}", "recommended_action": "ALERT"}


import google.generativeai as genai
import json
import os
from google.api_core.exceptions import GoogleAPICallError

# ===========================
# 1. API KEY HANDLING
# ===========================
API_KEY = os.getenv("GEMINI_API_KEY")

# If no environment variable, fallback to hardcoded (you asked for this)
if not API_KEY:
    API_KEY = "AIzaSyDei4mmgH9j_siUgUghKucxa0wgKhd_prQ"   # <-- YOUR KEY
    print("⚠️ WARNING: Using hardcoded API Key. Do NOT push this to GitHub.")

genai.configure(api_key=API_KEY)

# ===========================
# 2. Model Initialization
# ===========================
MODEL_NAME = "gemini-2.5-flash"
model = genai.GenerativeModel(MODEL_NAME)

# ===========================
# 3. LLM Prompt
# ===========================
PROMPT_LLM = """
You are a highly skilled cybersecurity network analyst specializing in threat detection.
Analyze the following comprehensive HTTP flow context provided in JSON format.
Focus on 'tags', payload patterns, suspicious hostnames, encoded data, 
high entropy indicators, and unauthorized network behavior.

Your recommended action MUST be exactly one of:
ALLOW, BLOCK, REJECT, LOG, WARN, ALERT.

FULL CONTEXT:
{payload}

Return ONLY this JSON object:
{
  "risk_level": "low|medium|high|critical",
  "explanation": "Short reasoning",
  "recommended_action": "ALLOW|BLOCK|REJECT|LOG|WARN|ALERT"
}
"""

# ===========================
# 4. Analyze Function
# ===========================
def analyze(llm_context: dict) -> dict:
    try:
        prompt = PROMPT_LLM.format(payload=json.dumps(llm_context, indent=2, ensure_ascii=False))

        response = model.generate_content(
            prompt,
            # ✅ This replaces GenerateContentConfig
            safety_settings={
                "HARASSMENT": "BLOCK_NONE",
                "HATE_SPEECH": "BLOCK_NONE",
                "SEXUALLY_EXPLICIT": "BLOCK_NONE",
            }
        )

        cleaned = response.text.strip().replace("```json", "").replace("```", "")
        return json.loads(cleaned)

    except GoogleAPICallError as e:
        return {"risk_level": "critical", "explanation": f"Gemini API error: {e}", "recommended_action": "ALERT"}

    except json.JSONDecodeError:
        # print first 200 chars for debug
        return {"risk_level": "critical", "explanation": "Invalid JSON returned from model", "recommended_action": "ALERT"}

    except Exception as e:
        return {"risk_level": "critical", "explanation": f"Unexpected error: {e}", "recommended_action": "ALERT"}
