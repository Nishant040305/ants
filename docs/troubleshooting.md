# Troubleshooting Guide

Common issues and solutions for ANTS deployment and operation.

## 🚨 Quick Diagnostics

### System Check
```bash
# Run comprehensive system check
python ants.py --system-check

# Test specific components
python ants.py --test-proxy
python ants.py --test-certificates
python ants.py --test-api-keys
python ants.py --test-rules
```

### Health Status
```bash
# Check current status
python ants.py --status

# Monitor real-time health
python ants.py --monitor

# Generate diagnostic report
python ants.py --diagnostic-report
```

## 🔧 Installation Issues

### Python Version Problems
```bash
# Issue: "Python 3.8+ required" 
# Check current version
python --version

# Solutions:
# 1. Install Python 3.8+ from python.org
# 2. Use pyenv to manage versions
pyenv install 3.9.16
pyenv local 3.9.16

# 3. Use specific Python executable
python3.9 -m venv .venv
```

### Dependency Installation Failures
```bash
# Issue: pip install failures
# Clear pip cache
pip cache purge

# Upgrade pip
python -m pip install --upgrade pip

# Install with verbose output
pip install -r requirements.txt -v

# Use different index
pip install -r requirements.txt -i https://pypi.org/simple/

# Install without cache
pip install -r requirements.txt --no-cache-dir
```

### Permission Errors
```bash
# Issue: Permission denied during installation
# Windows: Run PowerShell as Administrator
# Linux/Mac: Use sudo for system operations
sudo python -m pip install -r requirements.txt

# Or install to user directory
pip install -r requirements.txt --user

# Fix ownership issues (Linux/Mac)
sudo chown -R $USER:$USER ~/.local/
```

### Virtual Environment Issues
```bash
# Issue: Virtual environment not working
# Recreate virtual environment
rm -rf .venv
python -m venv .venv

# Windows activation issues
.venv\Scripts\activate.bat  # Command Prompt
.venv\Scripts\Activate.ps1  # PowerShell

# Linux/Mac activation issues
source .venv/bin/activate
```

## 🌐 Network & Proxy Issues

### Proxy Not Working
```bash
# Issue: No traffic captured
# Check if proxy is running
netstat -an | grep :8080
# Should show LISTENING on port 8080

# Test proxy directly
curl -v --proxy http://127.0.0.1:8080 http://httpbin.org/ip

# Check system proxy settings (Windows)
netsh winhttp show proxy

# Check browser proxy settings
# Chrome: Settings > Advanced > System > Open proxy settings
# Firefox: Settings > Network Settings
```

### Proxy Configuration Failures
```powershell
# Issue: "Access denied" when setting proxy
# Windows: Run PowerShell as Administrator
Start-Process PowerShell -Verb RunAs

# If still failing, check UAC settings
# Control Panel > User Account Control Settings
```

### Port Conflicts
```bash
# Issue: "Port already in use"
# Find process using port 8080
# Windows:
netstat -ano | findstr :8080
taskkill /PID <process_id> /F

# Linux/Mac:
lsof -i :8080
kill -9 <process_id>

# Use different port
python ants.py --port 8081
```

## 🔒 Certificate Issues

### Certificate Installation Failures
```bash
# Issue: Certificate not installing
# Windows: Run as Administrator
certutil -addstore -enterprise -f "Root" "%USERPROFILE%\.mitmproxy\mitmproxy-ca-cert.cer"

# Linux: Update certificate store
sudo update-ca-certificates

# macOS: Check keychain access
security find-certificate -c mitmproxy /Library/Keychains/System.keychain
```

### HTTPS Errors
```bash
# Issue: SSL certificate verification failed
# Check certificate is installed
python scripts/verify_certificate.py

# Regenerate certificates
rm -rf ~/.mitmproxy/
python ants.py --generate-certificates

# Temporarily allow insecure certificates (not recommended)
python ants.py --allow-insecure-certs
```

### Browser Certificate Warnings
```bash
# Issue: Browser showing certificate warnings
# Clear browser cache and certificates
# Chrome: Settings > Privacy and security > Clear browsing data > Cached files
# Firefox: Settings > Privacy & Security > Certificates > View Certificates

# Restart browser after certificate installation
# Some browsers require restart to recognize new certificates
```

## 🤖 AI Analysis Issues

### API Key Problems
```bash
# Issue: "Invalid API key"
# Check .env file exists and has correct format
cat .env | grep API_KEY

# Test API key directly
python scripts/test_api_keys.py

# Regenerate API key from provider
# Google: https://makersuite.google.com/app/apikey
# OpenAI: https://platform.openai.com/api-keys
```

### API Rate Limiting
```bash
# Issue: "Rate limit exceeded"
# Check API usage and limits
python scripts/check_api_usage.py

# Reduce analysis frequency
python ants.py --analysis-interval 60  # seconds

# Use different model with higher limits
python ants.py --model gemini-1.5-pro
```

### Analysis Timeouts
```bash
# Issue: AI analysis timing out
# Increase timeout
python ants.py --analysis-timeout 600  # 10 minutes

# Reduce payload size sent to AI
python ants.py --max-analysis-payload 1024  # 1KB

# Disable AI for high-traffic testing
python ants.py --no-ai
```

## 📊 Performance Issues

### High Memory Usage
```bash
# Issue: Excessive memory consumption
# Limit memory usage
python ants.py --max-memory 2GB

# Enable memory profiling
python ants.py --profile-memory

# Reduce cache sizes
python ants.py --cache-size 100

# Enable streaming mode
python ants.py --streaming
```

### High CPU Usage
```bash
# Issue: High CPU utilization
# Reduce concurrent processing
python ants.py --max-concurrent 5

# Disable verbose logging
python ants.py --quiet

# Profile CPU usage
python ants.py --profile-cpu

# Use more efficient rules only
python ants.py --rules "auth_token_leak,xss_payload"
```

### Slow Response Times
```bash
# Issue: Analysis taking too long
# Enable async processing
python ants.py --async-analysis

# Reduce rule complexity
python ants.py --simple-rules-only

# Increase worker threads
python ants.py --workers 8

# Use SSD for log storage
# Move logs directory to SSD
```

## 📁 File & Storage Issues

### Log File Problems
```bash
# Issue: Cannot write to log files
# Check permissions
ls -la logs/
chmod 755 logs/
chmod 644 logs/*.jsonl

# Check disk space
df -h
du -sh logs/

# Rotate old logs
python scripts/rotate_logs.py --keep-days 30
```

### Database Errors
```bash
# Issue: SQLite database errors
# Check database file
sqlite3 logs/events.db ".schema"

# Rebuild database
rm logs/events.db
python ants.py --init-database

# Check database permissions
chmod 644 logs/events.db
```

### Configuration File Issues
```bash
# Issue: Configuration not loading
# Validate YAML syntax
python -c "import yaml; yaml.safe_load(open('config.yaml'))"

# Check file permissions
ls -la config.yaml
chmod 644 config.yaml

# Use absolute paths
export ANTS_CONFIG=/full/path/to/config.yaml
```

## 🔍 Debug Mode

### Enable Debugging
```bash
# Enable all debugging
python ants.py --debug --verbose --trace

# Debug specific components
python ants.py --debug-proxy
python ants.py --debug-rules
python ants.py --debug-ai

# Save debug output
python ants.py --debug --debug-file debug.log 2>&1
```

### Log Analysis
```bash
# Analyze debug logs
grep "ERROR" debug.log
grep "WARNING" debug.log
grep "CRITICAL" debug.log

# Monitor logs in real-time
tail -f debug.log | grep -E "(ERROR|WARNING|CRITICAL)"
```

## 🆘 Getting Help

### Collect System Information
```bash
# Generate comprehensive diagnostic report
python ants.py --diagnostic-report > diagnostic.txt

# Include:
# - OS and Python version
# - Installed packages
# - Configuration files
# - Recent log entries
# - Network configuration
```

### Report Issues
When reporting issues, include:
1. **System Information**: OS, Python version, ANTS version
2. **Error Messages**: Complete error output
3. **Configuration**: Relevant config files (redact sensitive info)
4. **Steps to Reproduce**: Exact commands and actions
5. **Expected vs Actual Behavior**: What you expected vs what happened

### Community Resources
- **GitHub Issues**: https://github.com/Nishant040305/ants/issues
- **Documentation**: Complete docs in `docs/` directory
- **Examples**: Sample configurations in `examples/` directory
- **Scripts**: Diagnostic scripts in `scripts/` directory

## 📋 Common Error Messages

### "ModuleNotFoundError: No module named 'mitmproxy'"
```bash
# Solution: Install dependencies
pip install -r requirements.txt

# Or install specific package
pip install mitmproxy
```

### "Permission denied: '/etc/hosts'"
```bash
# Solution: Run with appropriate privileges
sudo python ants.py  # Linux/Mac
# Run PowerShell as Administrator (Windows)
```

### "Address already in use"
```bash
# Solution: Use different port or kill existing process
python ants.py --port 8081
# Or kill process using port
lsof -ti:8080 | xargs kill -9
```

### "SSL: CERTIFICATE_VERIFY_FAILED"
```bash
# Solution: Install MITM certificate
python scripts/install_certificate.py
# Or temporarily bypass (not recommended)
python ants.py --allow-insecure-certs
```

### "API quota exceeded"
```bash
# Solution: Check API usage and upgrade plan
# Or use different model/provider
python ants.py --model gpt-3.5-turbo  # Cheaper option
```

## 🔄 Recovery Procedures

### Reset Configuration
```bash
# Reset to defaults
rm config.yaml .env
python ants.py --generate-config > config.yaml
python ants.py --generate-env > .env
```

### Clean Installation
```bash
# Complete clean reinstall
rm -rf .venv logs __pycache__
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# or .venv\Scripts\activate  # Windows
pip install -r requirements.txt
```

### Emergency Stop
```bash
# Stop all ANTS processes
pkill -f ants.py  # Linux/Mac
taskkill /F /IM python.exe  # Windows (be careful!)

# Reset proxy settings
scripts/proxy_disable.sh  # Linux/Mac
scripts\proxy_disable.bat  # Windows
```

---

*If you continue to experience issues after trying these solutions, please create a GitHub issue with detailed information about your environment and the problem.*