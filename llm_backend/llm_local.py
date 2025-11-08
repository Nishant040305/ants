import os
import json
from llama_cpp import Llama
from pathlib import Path

# --- LLM Configuration (Unchanged) ---
MODEL_PATH = os.path.join("models", "phi3-mini-128k-instruct.Q4_K_S.gguf")

try:
    llm = Llama(
        model_path=MODEL_PATH,
        n_ctx=4096,
        n_threads=6,
        verbose=False,
    )
except Exception as e:
    print(f"Error loading LLM model from {MODEL_PATH}. Ensure llama-cpp is installed and the GGUF file exists.")
    print(f"Details: {e}")
    # Exit or handle the error appropriately if the model fails to load
    # raise

PROMPT = """
You are a cybersecurity network analyst.
Analyze the following flow summary and classify risk.

Flow:
{payload}

Respond ONLY in JSON:
{{
  "risk_level": "low|medium|high",
  "explanation": "short explanation",
  "recommended_action": "short recommended fix"
}}
"""

def analyze(summary: dict) -> dict:
    """
    Analyzes a single flow summary using the local Llama LLM (Phi-3).
    """
    try:
        text = PROMPT.format(payload=json.dumps(summary, ensure_ascii=False))
        out = llm(text, max_tokens=256, temperature=0.2)
        
        # The result includes the raw text output from the model
        result = out["choices"][0]["text"].strip()
        
        # Clean up any residual markdown fences (```json, ```) which LLMs sometimes add
        cleaned_result = result.replace("```json", "").replace("```", "").strip()
        
        # Attempt to parse the JSON output
        return json.loads(cleaned_result)
    
    except json.JSONDecodeError:
        print(f"\n[Error] LLM output was not valid JSON. Raw output: {result[:100]}...")
        return {"risk_level": "error", "explanation": "LLM returned non-JSON data.", "recommended_action": "Review model output constraints."}
    except Exception as e:
        print(f"[Error] Failed during LLM generation or processing: {e}")
        return {"risk_level": "error", "explanation": f"Processing failed: {e}", "recommended_action": "Check llama-cpp status."}

# --- New Function to Process Log File ---

def process_log_file(file_path: str, output_path: str):
    """
    Reads a JSON Lines (.jsonl) file, processes each line (flow) using the LLM,
    and saves the analysis results to a new file.
    """
    input_file = Path(file_path)
    output_file = Path(output_path)
    
    if not input_file.exists():
        print(f"❌ Error: Input file not found at {file_path}")
        return

    print(f"🔍 Starting analysis of flows from: {input_file.name}")
    
    total_flows = 0
    analyzed_flows = 0
    
    with open(input_file, 'r', encoding='utf-8') as infile, \
         open(output_file, 'w', encoding='utf-8') as outfile:
        
        for line in infile:
            total_flows += 1
            line = line.strip()
            if not line:
                continue

            try:
                # 1. Load the flow summary from the JSON line
                summary = json.loads(line)
                
                # 2. Perform the LLM analysis
                analysis = analyze(summary)
                
                # 3. Combine original summary and new analysis
                summary["llm_analysis"] = analysis
                
                # 4. Write the combined result to the output file
                outfile.write(json.dumps(summary, ensure_ascii=False) + "\n")
                
                analyzed_flows += 1
                
                # Print a progress update
                print(f"✅ Processed flow {total_flows}: Risk={analysis.get('risk_level', 'N/A')}")
                
            except json.JSONDecodeError:
                print(f"⚠️ Warning: Skipped line {total_flows} due to invalid JSON formatting in the input file.")
            except Exception as e:
                print(f"❌ Error processing line {total_flows}: {e}")

    print(f"\n--- Analysis Complete ---")
    print(f"Total lines processed: {total_flows}")
    print(f"Successfully analyzed flows: {analyzed_flows}")
    print(f"Results saved to: {output_file.resolve()}")


# --- Execution Example ---
if __name__ == "__main__":
    # Define the input and output file paths
    INPUT_LOG_FILE = "mitm_logs/mitm_logs/mitm-2025-11-08.jsonl"  # <-- Use your actual log file name
    OUTPUT_RESULT_FILE = "mitm_logs/llm_analyzed_results.jsonl"
    
    process_log_file(INPUT_LOG_FILE, OUTPUT_RESULT_FILE)