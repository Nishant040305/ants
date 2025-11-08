# Frequently Asked Questions (FAQ)

Common questions and answers about ANTS usage, configuration, and troubleshooting.

## 🚀 Getting Started

### Q: What does ANTS do?
**A:** ANTS (Advanced Network Traffic Security Analyzer) is a sophisticated HTTP/HTTPS packet analyzer that uses both rule-based detection and AI-powered analysis to identify security threats in web traffic. It acts as a MITM proxy to intercept and analyze network communications in real-time.

### Q: Do I need special permissions to run ANTS?
**A:** Yes, ANTS requires:
- **Windows**: Administrator privileges for proxy configuration
- **Linux/Mac**: Sudo access for network interface manipulation and certificate installation
- **All platforms**: Permission to install SSL certificates for HTTPS analysis

### Q: Is ANTS safe to use?
**A:** Yes, when used responsibly. ANTS is designed for authorized security testing and monitoring. Always ensure you have permission to monitor the traffic you're analyzing, and follow applicable laws and regulations.

## 🔧 Installation & Setup

### Q: What Python version do I need?
**A:** Python 3.8 or higher is required. Python 3.9+ is recommended for best performance and compatibility.

### Q: Do I need API keys to use ANTS?
**A:** API keys are optional but recommended:
- **Without API keys**: Static rule-based analysis works perfectly
- **With API keys**: Enables AI-powered threat analysis for flagged traffic
- **Supported APIs**: Google Gemini, OpenAI GPT, Anthropic Claude

### Q: Can I run ANTS without internet access?
**A:** Yes, partially:
- **Rule-based analysis**: Works completely offline
- **AI analysis**: Requires internet connection to API providers
- **Certificate validation**: May require internet for some certificate operations

## 🌐 Network & Proxy

### Q: Why do I need to install a certificate?
**A:** ANTS uses a MITM proxy to analyze HTTPS traffic. The certificate allows ANTS to decrypt and analyze encrypted communications while maintaining security. Without it, you'll see certificate warnings and won't be able to analyze HTTPS traffic.

### Q: Will ANTS slow down my internet connection?
**A:** Minimal impact in most cases:
- **Light analysis**: ~5-10ms additional latency
- **AI analysis enabled**: Slightly higher latency for flagged requests
- **Performance can be tuned**: Adjust concurrent connections and analysis settings

### Q: Can I use ANTS with my existing proxy?
**A:** Yes, ANTS supports upstream proxy chaining:
```bash
python ants.py --upstream-proxy "your-proxy.com:8080"
```

### Q: What ports does ANTS use?
**A:** Default configuration:
- **MITM Proxy**: Port 8080 (configurable)
- **Web Interface**: Port 8081 (if enabled)
- **API Connections**: Outbound HTTPS (443) to AI providers

## 🛡️ Security & Privacy

### Q: Does ANTS store sensitive data?
**A:** ANTS follows security best practices:
- **Sensitive headers**: Detected but not stored in logs by default
- **Payload content**: Configurable inclusion in logs
- **API keys**: Never logged or transmitted except to authorized APIs
- **Certificate data**: Stored securely in system certificate stores

### Q: Can ANTS analyze my company's internal traffic?
**A:** Yes, but consider:
- **Legal requirements**: Ensure compliance with company policies and laws
- **Privacy concerns**: Configure appropriate data retention and access controls
- **Network policies**: May need approval from IT/Security teams
- **Sensitive data**: Consider excluding internal domains from analysis

### Q: How do I remove ANTS completely?
**A:** Complete removal process:
```bash
# 1. Disable proxy settings
scripts/proxy_disable.sh  # Linux/Mac
scripts\proxy_disable.bat  # Windows

# 2. Remove certificates
scripts/remove_certificates.sh  # Linux/Mac
scripts\remove_certificates.bat  # Windows

# 3. Remove application
rm -rf ants/  # Linux/Mac
rmdir /s ants\  # Windows
```

## 📊 Analysis & Results

### Q: What types of threats can ANTS detect?
**A:** ANTS detects various security issues:
- **Authentication**: Token leakage, credential exposure
- **Injection attacks**: XSS, SQL injection, command injection
- **Data exfiltration**: Large uploads, suspicious data transfers
- **Malware communication**: C2 patterns, beaconing
- **Reconnaissance**: Admin path probing, scanner tools
- **Policy violations**: Untrusted domains, suspicious user agents

### Q: How accurate is the AI analysis?
**A:** AI analysis accuracy depends on several factors:
- **Model quality**: Gemini Pro/GPT-4 provide high accuracy
- **Context provided**: More context improves accuracy
- **Threat type**: Some threats are easier to detect than others
- **False positive rate**: Typically <5% with proper configuration

### Q: Can I customize the security rules?
**A:** Absolutely! ANTS supports:
- **Enable/disable rules**: Configure which built-in rules to use
- **Custom rules**: Write your own detection logic in Python
- **Rule sensitivity**: Adjust thresholds and parameters
- **Rule priorities**: Configure response actions (ALERT, BLOCK, etc.)

### Q: What output formats are supported?
**A:** ANTS provides multiple output formats:
- **JSONL**: Primary format for logs (newline-delimited JSON)
- **JSON**: Structured analysis reports
- **CSV**: Tabular data for spreadsheet analysis
- **Console**: Real-time colored output
- **Web dashboard**: Visual interface (optional)

## 🔧 Configuration & Customization

### Q: How do I configure ANTS for my environment?
**A:** ANTS offers flexible configuration:
- **Environment variables**: `.env` file for sensitive settings
- **Configuration files**: YAML files for detailed settings
- **Command line**: Override settings for specific runs
- **Profiles**: Pre-defined configurations for different scenarios

### Q: Can I run multiple ANTS instances?
**A:** Yes, with different configurations:
```bash
# Different ports
python ants.py --port 8080  # Instance 1
python ants.py --port 8081  # Instance 2

# Different configurations
python ants.py --config production.yaml
python ants.py --config development.yaml
```

### Q: How do I handle high-traffic environments?
**A:** Performance optimization strategies:
- **Selective analysis**: Filter traffic by host, path, or method
- **Disable AI**: Use only rule-based analysis for speed
- **Increase resources**: More CPU cores and memory
- **Async processing**: Enable asynchronous analysis
- **Load balancing**: Distribute across multiple instances

## 🐛 Troubleshooting

### Q: ANTS isn't capturing any traffic. What's wrong?
**A:** Common causes and solutions:
1. **Proxy not configured**: Verify browser/system proxy settings
2. **Certificate issues**: Install and trust the MITM certificate
3. **Port conflicts**: Another application might be using port 8080
4. **Firewall blocking**: Allow ANTS through firewall
5. **Virtual environment**: Ensure you're in the correct Python environment

### Q: I'm getting certificate errors in my browser.
**A:** Certificate troubleshooting:
1. **Install certificate**: Follow platform-specific installation guide
2. **Restart browser**: Some browsers require restart after certificate installation
3. **Clear cache**: Clear browser cache and certificates
4. **Regenerate certificate**: Delete `~/.mitmproxy/` and restart ANTS
5. **Check trust settings**: Ensure certificate is trusted for SSL

### Q: AI analysis isn't working.
**A:** AI analysis troubleshooting:
1. **Check API keys**: Verify keys are correct in `.env` file
2. **Test connectivity**: Ensure internet access to API providers
3. **Check quotas**: Verify you haven't exceeded API rate limits
4. **Model availability**: Some models may be temporarily unavailable
5. **Payload size**: Large payloads might cause timeouts

## 💡 Best Practices

### Q: What are the recommended settings for production use?
**A:** Production configuration recommendations:
- **Security**: Strict certificate validation, audit logging
- **Performance**: Appropriate resource limits, async processing
- **Reliability**: Error handling, automatic restarts
- **Monitoring**: Health checks, performance metrics
- **Compliance**: Data retention policies, access controls

### Q: How should I organize my analysis results?
**A:** Result organization strategies:
- **Separate environments**: Different log directories for dev/prod
- **Time-based rotation**: Daily/weekly log rotation
- **Priority-based filing**: Separate high-priority alerts
- **Automated processing**: Scripts to process and archive results
- **Integration**: Forward results to SIEM or monitoring systems

### Q: Any tips for getting started?
**A:** Getting started recommendations:
1. **Start simple**: Begin with basic rule-based analysis
2. **Test environment**: Use on non-production traffic first
3. **Gradual enablement**: Enable features incrementally
4. **Monitor resources**: Watch CPU, memory, and disk usage
5. **Read documentation**: Review guides for your specific use case
6. **Join community**: Engage with other users for tips and tricks

## 🔗 Additional Resources

### Q: Where can I find more help?
**A:** Additional support resources:
- **Documentation**: Complete guides in `docs/` directory
- **GitHub Issues**: Report bugs and request features
- **Examples**: Sample configurations in `examples/` directory
- **Scripts**: Utility scripts in `scripts/` directory
- **Community**: Connect with other ANTS users

### Q: How do I contribute to ANTS?
**A:** Contribution opportunities:
- **Bug reports**: Report issues on GitHub
- **Feature requests**: Suggest new capabilities
- **Code contributions**: Submit pull requests
- **Documentation**: Improve guides and examples
- **Testing**: Help test new features and releases

### Q: Is there a roadmap for future features?
**A:** Upcoming features and improvements:
- **Enhanced AI models**: Support for newer LLM models
- **Performance optimization**: Better resource efficiency
- **Additional protocols**: Support for more network protocols
- **Cloud integration**: Better cloud and container support
- **Enterprise features**: Advanced management and monitoring

---

*Don't see your question here? Check the [Troubleshooting Guide](troubleshooting.md) or open a GitHub issue.*