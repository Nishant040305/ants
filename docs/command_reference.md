# Command Reference

Complete reference for all ANTS commands and scripts.

## 🚀 Main Application

### Basic Usage
```bash
# Start ANTS with default settings
python ants.py

# Start with specific configuration
python ants.py --config config.yaml

# Enable debug mode
python ants.py --debug

# Show version information
python ants.py --version

# Run self-tests
python ants.py --test
```

### Command Line Options
```bash
# General options
--config PATH          Configuration file path
--debug               Enable debug logging
--verbose             Verbose output
--quiet               Suppress output
--version             Show version and exit
--help                Show help message

# Network options
--host HOST           MITM proxy host (default: 127.0.0.1)
--port PORT           MITM proxy port (default: 8080)
--no-proxy            Skip proxy configuration

# Analysis options
--rules RULES         Comma-separated list of rules to enable
--no-ai               Disable AI analysis
--model MODEL         AI model to use (gemini-pro, gpt-4, claude-3)
--max-logs N          Maximum logs to process

# Output options
--output-dir DIR      Output directory for logs
--format FORMAT       Output format (json, csv, yaml)
--no-color            Disable colored output
```

## 🔧 Proxy Management

### Windows Proxy Setup
```powershell
# Enable system proxy (run as Administrator)
netsh winhttp set proxy 127.0.0.1:8080

# Enable browser proxy (normal PowerShell)
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyServer -Value "127.0.0.1:8080"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyEnable -Value 1

# Install MITM certificate
certutil -addstore -enterprise -f "Root" "%USERPROFILE%\.mitmproxy\mitmproxy-ca-cert.cer"
```

### Windows Proxy Cleanup
```powershell
# Disable system proxy (run as Administrator)
netsh winhttp reset proxy

# Disable browser proxy (normal PowerShell)
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyEnable -Value 0

# Remove MITM certificate
Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -like "*mitmproxy*" } | Remove-Item -Force
```


#Run LocalMachine# Set your API key
export GOOGLE_API_KEY="your-api-key"  # For Gemini
# or
export OPENAI_API_KEY="your-api-key"  # For OpenAI
# or
export ANTHROPIC_API_KEY="your-api-key"  # For Claude

# List available analyzers
python log_analyzer.py --list-analyzers

# Analyze with default model (Gemini)
python log_analyzer.py mitm_logs/mitm-2025-11-08.jsonl

# Specify analyzer and model
python log_analyzer.py mitm_logs/mitm-2025-11-08.jsonl --analyzer openai --model gpt-4
python log_analyzer.py mitm_logs/mitm-2025-11-08.jsonl --analyzer claude --model claude-3-opus-20240229

# Limit number of logs to process
python log_analyzer.py mitm_logs/mitm-2025-11-08.jsonl --max-logs 5

# Save results to a specific file
python log_analyzer.py mitm_logs/mitm-2025-11-08.jsonl --output my_analysis.json