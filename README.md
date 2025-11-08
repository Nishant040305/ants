# ANTS - Advanced Network Traffic Security Analyzer

A sophisticated HTTP packet analyzer and security monitoring tool with AI-powered threat detection capabilities.

![ANTS Logo](https://img.shields.io/badge/ANTS-Network%20Security-blue) ![Python](https://img.shields.io/badge/Python-3.8+-green) ![License](https://img.shields.io/badge/License-MIT-yellow)

## 🚀 Quick Start

### Windows
```cmd
# Start the analyzer
ants.bat

# Or enable proxy and start MITM
scripts\proxy_enable.bat
scripts\mitm_start.bat
```

### Python/Linux
```bash
# Start the analyzer
python ants.py

# Install dependencies
pip install -r requirements.txt
```

## 📁 Project Structure

```
ants/
├── ants.py                 # Main application entry point
├── ants.bat               # Windows launcher
├── scripts/               # Core analysis scripts
│   ├── proxy_enable.bat   # Enable system proxy (was: add_proxy.bat)
│   ├── proxy_disable.bat  # Disable system proxy (was: remove_proxy.bat)
│   ├── mitm_start.bat     # Start MITM proxy (was: run.bat)
│   ├── log_analyzer.py    # Log analysis engine (was: analyze_mitm_logs.py)
│   ├── payload_printer.py # Payload display utility (was: print_payloads.py)
│   ├── flow_saver.py      # Flow persistence (was: save_flow.py)
│   ├── packet_filter.py   # Packet filtering engine (was: save_packet_filtered.py)
│   └── security_rules.py  # Security rule definitions (was: static_rules.py)
├── logs/                  # Analysis outputs and logs
│   ├── mitm_logs/        # Raw MITM proxy logs
│   └── events.db         # Event database
├── docs/                  # Documentation
│   ├── analyzer_guide.md              # Main analyzer documentation
│   ├── security_rules_reference.md    # Security rules development history
│   ├── packet_filter_reference.md     # Packet filter development history
│   ├── command_reference.txt          # Command reference
│   └── project_reorganization_summary.md
├── archive/               # Legacy and archived code
└── src/                  # Core application modules
```

## 🛠️ Core Features

### 🔍 **Traffic Analysis**
- **Real-time HTTP/HTTPS packet capture** via MITM proxy
- **AI-powered threat detection** using LLM analysis
- **Multi-layered security rule engine** with STRIDE threat modeling
- **Compressed payload decompression** (gzip, deflate, zlib)

### 🚨 **Security Detection**
- **Authentication token leakage** detection
- **Command & Control (C2)** communication patterns
- **Data exfiltration** monitoring (large uploads/downloads)
- **XSS and injection** payload detection
- **Suspicious user agents** and scanning tools
- **Internal IP references** (SSRF detection)

### 📊 **Analysis Outputs**
- **Compact summaries** for all traffic (`summary-YYYY-MM-DD.jsonl`)
- **Detailed alerts** for flagged traffic (`alerts-YYYY-MM-DD.jsonl`)
- **Full packet captures** for incidents (`full-YYYY-MM-DD.jsonl`)
- **AI risk assessments** with recommended actions

## 🔧 Configuration

### Environment Setup
```bash
# Copy environment template
cp .env.example .env

# Configure your settings
GEMINI_API_KEY=your_api_key_here
MITM_PORT=8080
LOG_LEVEL=INFO
```

### Security Rules
Security rules are defined in `scripts/security_rules.py` with priority levels:

1. **ALERT** - Critical threats (auth token leaks, sensitive file access)
2. **BLOCK** - High-risk activities (large uploads, C2 indicators)
3. **REJECT** - Policy violations (malicious user agents, admin probes)
4. **WARN** - Suspicious activities (untrusted domains, unusual ports)
5. **LOG** - Informational events (telemetry, tracking)

## 📖 Usage Examples

### Basic Traffic Monitoring
```bash
# Start with default settings
python ants.py

# Monitor specific host
python ants.py --host example.com

# Enable verbose logging
python ants.py --verbose
```

### Advanced Analysis
```bash
# Analyze existing logs
python scripts/log_analyzer.py --input logs/mitm_logs/

# Print payloads in real-time
python scripts/payload_printer.py --max-size 1024

# Custom rule filtering
python scripts/packet_filter.py --rules auth_token_leak,xss_payload
```

### Proxy Management
```cmd
# Windows proxy setup
scripts\proxy_enable.bat    # Enable system proxy
scripts\mitm_start.bat      # Start MITM server
scripts\proxy_disable.bat   # Disable when done
```

## 🔬 Analysis Pipeline

1. **Traffic Capture** - MITM proxy intercepts HTTP/HTTPS traffic
2. **Rule Matching** - Static security rules evaluate each request
3. **Payload Processing** - Decompress and decode response bodies
4. **AI Analysis** - LLM evaluates flagged traffic for threat assessment
5. **Multi-tier Logging** - Save summaries, alerts, and full packets
6. **Action Prioritization** - Determine highest-priority security response

### Sample Output
```json
{
  "host": "suspicious-site.com",
  "method": "POST",
  "tags": ["auth_token_leak", "untrusted_domain"],
  "analysis": {
    "risk_level": "HIGH",
    "recommended_action": "BLOCK",
    "reasoning": "Authorization header detected to untrusted domain"
  }
}
```

## 🔒 Security Features

### STRIDE Threat Coverage
- **Spoofing**: Domain/IP validation, user agent analysis
- **Tampering**: XSS detection, suspicious HTTP methods
- **Repudiation**: Comprehensive logging and audit trails
- **Information Disclosure**: Token leakage, sensitive file access
- **Denial of Service**: Large upload detection, resource monitoring
- **Elevation of Privilege**: Admin path probing, privilege escalation attempts

### AI Integration
- **Context-aware analysis** using Google Gemini
- **Risk level assessment** (NONE, LOW, MEDIUM, HIGH, CRITICAL)
- **Actionable recommendations** (ALLOW, LOG, WARN, REJECT, BLOCK, ALERT)
- **Payload content analysis** for advanced threat detection

## 📚 Documentation

- **[Analyzer Guide](docs/analyzer_guide.md)** - Detailed usage and configuration
- **[Security Rules Reference](docs/security_rules_reference.md)** - Rule development history
- **[Packet Filter Reference](docs/packet_filter_reference.md)** - Filter implementation details
- **[Command Reference](docs/command_reference.txt)** - CLI command examples

## 🧪 Development

### File Naming Convention
Recent reorganization introduced clearer naming:
- `proxy_enable.bat` ← `add_proxy.bat`
- `proxy_disable.bat` ← `remove_proxy.bat`
- `mitm_start.bat` ← `run.bat`
- `log_analyzer.py` ← `analyze_mitm_logs.py`
- `payload_printer.py` ← `print_payloads.py`
- `flow_saver.py` ← `save_flow.py`
- `packet_filter.py` ← `save_packet_filtered.py`
- `security_rules.py` ← `static_rules.py`

### Adding Custom Rules
1. Define rule function in `scripts/security_rules.py`
2. Add to `STATIC_RULES` list with appropriate priority
3. Update action mapping for desired response
4. Test with sample traffic

### Contributing
1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## ⚡ Performance

- **Real-time processing** with minimal latency overhead
- **Efficient rule matching** using optimized static checks
- **Smart payload handling** with compression support
- **Selective AI analysis** only for flagged traffic
- **Multi-file logging** for performance and organization

## 🐛 Troubleshooting

### Common Issues
- **Proxy conflicts**: Ensure no other proxies are running on port 8080
- **Certificate errors**: Install MITM CA certificate for HTTPS
- **Permission issues**: Run with administrator privileges on Windows
- **API limits**: Monitor Gemini API usage and rate limits

### Debug Mode
```bash
# Enable debug logging
python ants.py --debug

# Check proxy status
netstat -an | findstr :8080

# Verify rule matching
python scripts/security_rules.py --test
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Acknowledgments

- **mitmproxy** for excellent HTTP proxy capabilities
- **Google Gemini** for AI-powered threat analysis
- **STRIDE** methodology for comprehensive threat modeling
- **Community contributors** for security rule development

---

**⚠️ Disclaimer**: This tool is for authorized security testing and monitoring only. Ensure compliance with applicable laws and regulations.