# Analysis Guide

Comprehensive guide to understanding and using ANTS analysis capabilities.

## 🎯 Analysis Overview

ANTS provides multi-layered security analysis combining:
- **Static Rule Engine**: Fast pattern matching for known threats
- **AI-Powered Analysis**: Context-aware threat assessment using LLMs
- **Behavioral Analysis**: Traffic pattern and anomaly detection
- **Risk Scoring**: Prioritized threat classification

## 📊 Analysis Pipeline

### 1. Traffic Capture
Real-time HTTP/HTTPS traffic interception via MITM proxy

### 2. Rule-Based Filtering
Initial filtering using static security rules:
- Authentication token detection
- Suspicious user agents
- Malicious payloads
- Data exfiltration patterns

### 3. AI Analysis
LLM evaluation of flagged traffic for:
- Context understanding
- Threat severity assessment
- Recommended actions
- Detailed reasoning

### 4. Multi-tier Logging
Results saved to structured files for different use cases

## Usage

### 1. Capture Traffic with MITM Proxy

1. **Set up system proxy** (Run as Administrator in PowerShell):
   ```powershell
   # Set system proxy
   netsh winhttp set proxy 127.0.0.1:8080
   
   # For browser proxy settings
   Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyServer -Value "127.0.0.1:8080"
   Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyEnable -Value 1
   
   # Install MITM certificate (run in normal PowerShell)
   certutil -addstore -enterprise -f "Root" "C:\Users\%USERNAME%\.mitmproxy\mitmproxy-ca-cert.cer"
   ```

2. **Start capturing traffic**:
   ```bash
   mitmproxy -s save_flow.py --listen-host 0.0.0.0 -p 8080
   ```

3. **When done, reset proxy settings** (Run as Administrator):
   ```powershell
   netsh winhttp reset proxy
   ```

This will create log files in the `mitm_logs/` directory with names like `mitm-YYYY-MM-DD.jsonl`.

### 2. Analyze Logs

To analyze the captured logs:

```bash
python analyze_mitm_logs.py mitm_logs/mitm-YYYY-MM-DD.jsonl --output analysis_results.json
```

### Command Line Options

- `log_file`: Path to mitmproxy log file (JSONL format)
- `--output`, `-o`: Output file for analysis results (JSON format)
- `--model`: Gemini model to use (default: gemini-pro)

### Example

```bash
# Basic usage
python analyze_mitm_logs.py mitm_logs/mitm-2025-11-08.jsonl

# Save results to file
python analyze_mitm_logs.py mitm_logs/mitm-2025-11-08.jsonl -o results/analysis_20251108.json

# Use a different Gemini model
python analyze_mitm_logs.py mitm_logs/mitm-2025-11-08.jsonl --model gemini-1.5-pro
```

## Output

The analyzer provides:
- Real-time progress updates
- Severity scores (0-10) for each request
- Security decisions (allow/alert/redact/block)
- Detailed reasoning for each decision
- Summary statistics

Results are saved in JSON format with the following structure:

```json
[
  {
    "timestamp": "2025-11-08T10:30:00Z",
    "request": "GET example.com/api/data",
    "analysis": {
      "severity": 8,
      "tags": ["api_key_detected", "sensitive_data"],
      "decision": "block",
      "reason": "API key found in URL parameters"
    },
    "severity": 8
  }
]
```

## Security Note

- The analyzer processes potentially sensitive data. Review the output carefully.
- API keys and tokens in the logs are analyzed but not stored in the results.
- Ensure your `.env` file with the API key is not committed to version control.
