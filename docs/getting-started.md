# Quick Start Guide

Get ANTS up and running in minutes with this streamlined guide.

## 🚀 Fast Setup (5 minutes)

### 1. Prerequisites Check
```bash
# Verify Python version (3.8+ required)
python --version

# Check if pip is available
pip --version
```

### 2. Installation
```bash
# Clone and enter project
git clone https://github.com/Nishant040305/ants.git
cd ants

# Install dependencies
pip install -r requirements.txt

# Set up environment
cp .env.example .env
# Edit .env with your API keys
```

### 3. Basic Usage

#### Windows (Recommended)
```cmd
# Start ANTS with GUI helper
ants.bat

# Or manually:
scripts\proxy_enable.bat      # Enable system proxy
scripts\mitm_start.bat        # Start traffic capture
# Browse the web to generate traffic
scripts\proxy_disable.bat     # Disable proxy when done
```

#### Linux/Mac
```bash
# Start ANTS
python ants.py

# Or step by step:
sudo python scripts/proxy_setup.py --enable
python scripts/mitm_start.py
# Generate traffic
sudo python scripts/proxy_setup.py --disable
```

### 4. View Results
```bash
# Check logs directory
ls logs/

# View analysis results
cat logs/alerts-YYYY-MM-DD.jsonl
```

## 🎯 What Happens Next?

1. **Traffic Capture**: ANTS captures HTTP/HTTPS traffic through a MITM proxy
2. **Rule Matching**: Built-in security rules evaluate each request
3. **AI Analysis**: Flagged traffic gets analyzed by LLM for threat assessment
4. **Logging**: Results saved to multiple files:
   - `summary-*.jsonl` - All traffic overview
   - `alerts-*.jsonl` - Flagged traffic with AI analysis
   - `full-*.jsonl` - Complete packet data for incidents

## 📊 Sample Output

```json
{
  "host": "api.example.com",
  "method": "POST", 
  "tags": ["auth_token_leak"],
  "analysis": {
    "risk_level": "HIGH",
    "recommended_action": "ALERT",
    "reasoning": "Authorization header contains bearer token"
  }
}
```

## ⚠️ Important Notes

- **Admin Privileges**: Required on Windows for proxy configuration
- **HTTPS Certificate**: Install MITM certificate for HTTPS analysis
- **API Keys**: Configure in `.env` for AI analysis features
- **Firewall**: May need to allow Python/mitmproxy through firewall

## 🔧 Quick Troubleshooting

| Issue | Solution |
|-------|----------|
| Permission denied | Run as administrator (Windows) or with sudo (Linux) |
| Certificate errors | Install MITM CA certificate |
| No traffic captured | Check proxy settings are applied |
| API errors | Verify API keys in `.env` file |

## 📖 Next Steps

- **[Installation Guide](installation.md)** - Detailed setup instructions
- **[Configuration Guide](configuration.md)** - Customize settings
- **[Traffic Capture Guide](traffic-capture.md)** - Advanced capture techniques
- **[Analysis Guide](analysis.md)** - Understanding results

## 🆘 Need Help?

- Check [Troubleshooting Guide](troubleshooting.md)
- Review [Command Reference](command-reference.md) 
- See [FAQ](faq.md) for common questions
- Open an issue on GitHub

---

*⏱️ Estimated setup time: 5-10 minutes*