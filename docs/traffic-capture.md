# Traffic Capture Guide

Complete guide to capturing and analyzing HTTP/HTTPS traffic with ANTS.

## 🎯 Traffic Capture Overview

ANTS uses a Man-in-the-Middle (MITM) proxy to intercept and analyze HTTP/HTTPS traffic in real-time. This approach provides complete visibility into encrypted communications while maintaining security through proper certificate management.

## 🚀 Quick Start Capture

### Automated Setup (Recommended)
```bash
# Windows
scripts\proxy_enable.bat      # Configure system proxy
scripts\mitm_start.bat        # Start traffic capture
# Browse web to generate traffic
scripts\proxy_disable.bat     # Clean up when done

# Linux/Mac
sudo scripts/proxy_enable.sh
scripts/mitm_start.sh
# Generate traffic
sudo scripts/proxy_disable.sh
```

### Manual Setup
```bash
# 1. Start ANTS
python ants.py --port 8080

# 2. Configure browser proxy
# Point browser to 127.0.0.1:8080

# 3. Install certificate (one-time setup)
# Visit http://mitm.it in configured browser
```

## 🔧 Proxy Configuration

### System-Wide Proxy (Windows)
```powershell
# Enable (run as Administrator)
netsh winhttp set proxy 127.0.0.1:8080

# Configure browser proxy settings
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyServer -Value "127.0.0.1:8080"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyEnable -Value 1

# Disable (run as Administrator)
netsh winhttp reset proxy
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyEnable -Value 0
```

### System-Wide Proxy (Linux)
```bash
# Enable
export http_proxy=http://127.0.0.1:8080
export https_proxy=http://127.0.0.1:8080

# Or system-wide
sudo scripts/proxy_enable.sh

# Disable
unset http_proxy https_proxy
sudo scripts/proxy_disable.sh
```

### Browser-Specific Proxy
Configure proxy in browser settings:
- **HTTP Proxy**: 127.0.0.1:8080
- **HTTPS Proxy**: 127.0.0.1:8080
- **SOCKS Proxy**: Not required

## 🔒 HTTPS Certificate Setup

### Automatic Installation
```bash
# Windows (run as Administrator)
scripts\install_certificate.bat

# Linux
sudo scripts/install_certificate.sh

# macOS
scripts/install_certificate_macos.sh
```

### Manual Installation

#### Windows
```powershell
# Find certificate
$certPath = "$env:USERPROFILE\.mitmproxy\mitmproxy-ca-cert.cer"

# Install to trusted root store
certutil -addstore -enterprise -f "Root" $certPath

# Verify installation
certutil -store Root | findstr mitmproxy
```

#### Linux (Ubuntu/Debian)
```bash
# Copy certificate
sudo cp ~/.mitmproxy/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy.crt

# Update certificate store
sudo update-ca-certificates

# Verify installation
openssl x509 -in /usr/local/share/ca-certificates/mitmproxy.crt -text -noout
```

#### macOS
```bash
# Install to system keychain
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/.mitmproxy/mitmproxy-ca-cert.pem

# Verify installation
security find-certificate -c mitmproxy /Library/Keychains/System.keychain
```

## 📱 Mobile Device Setup

### iOS Setup
1. Configure Wi-Fi proxy: 127.0.0.1:8080
2. Visit http://mitm.it in Safari
3. Download iOS certificate
4. Install via Settings > General > Profiles
5. Trust certificate in Settings > General > About > Certificate Trust Settings

### Android Setup
1. Configure Wi-Fi proxy: 127.0.0.1:8080
2. Visit http://mitm.it in browser
3. Download Android certificate
4. Install via Settings > Security > Encryption & credentials > Install a certificate

## 🌐 Advanced Capture Scenarios

### Corporate Environment
```yaml
# config/corporate.yaml
network:
  proxy:
    upstream_proxy: "corporate-proxy.company.com:8080"
    upstream_auth:
      username: "user"
      password: "pass"
  filtering:
    ignore_hosts:
      - "internal.company.com"
      - "*.corp.local"
```

### Cloud Environment
```yaml
# config/cloud.yaml
network:
  proxy:
    host: "0.0.0.0"  # Listen on all interfaces
    port: 8080
  security:
    allowed_clients:
      - "10.0.0.0/8"
      - "172.16.0.0/12"
      - "192.168.0.0/16"
```

### Container Environment
```dockerfile
# Dockerfile
FROM python:3.9
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
EXPOSE 8080
CMD ["python", "ants.py", "--host", "0.0.0.0"]
```

## 🔍 Selective Traffic Capture

### Host-Based Filtering
```bash
# Capture only specific hosts
python ants.py --hosts "api.example.com,secure.bank.com"

# Exclude hosts
python ants.py --exclude-hosts "cdn.example.com,static.assets.com"
```

### Path-Based Filtering
```bash
# Capture only API endpoints
python ants.py --paths "/api/*,/v1/*"

# Exclude static content
python ants.py --exclude-paths "*.jpg,*.png,*.css,*.js"
```

### Method-Based Filtering
```bash
# Capture only specific HTTP methods
python ants.py --methods "POST,PUT,DELETE"

# Exclude safe methods
python ants.py --exclude-methods "GET,HEAD,OPTIONS"
```

## 📊 Real-Time Monitoring

### Console Output
```bash
# Enable real-time console output
python ants.py --verbose --real-time

# Color-coded output
python ants.py --color

# Quiet mode (errors only)
python ants.py --quiet
```

### Web Interface
```bash
# Start with web interface
python ants.py --web-port 8081

# Access dashboard at http://localhost:8081
```

### Live Logs
```bash
# Follow live summary logs
tail -f logs/summary-$(date +%Y-%m-%d).jsonl

# Follow alerts
tail -f logs/alerts-$(date +%Y-%m-%d).jsonl | jq .
```

## 🎛️ Capture Modes

### Transparent Mode (Linux/Mac)
```bash
# Requires root privileges
sudo python ants.py --transparent --port 80,443

# Configure iptables rules
sudo iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-port 8080
sudo iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 8080
```

### Reverse Proxy Mode
```bash
# Act as reverse proxy for specific backend
python ants.py --reverse-proxy "https://backend.example.com"

# Multiple backends
python ants.py --reverse-proxy "api=https://api.example.com,web=https://web.example.com"
```

### Upstream Proxy Mode
```bash
# Chain with existing proxy
python ants.py --upstream-proxy "proxy.company.com:3128"

# With authentication
python ants.py --upstream-proxy "proxy.company.com:3128" --upstream-auth "user:pass"
```

## 🔧 Performance Optimization

### High-Traffic Environments
```yaml
# config/high-performance.yaml
performance:
  max_concurrent: 50
  buffer_size: 65536
  thread_pool: 8
  async_logging: true

network:
  tcp_nodelay: true
  socket_reuse: true
  keep_alive: true
```

### Memory Management
```bash
# Limit memory usage
python ants.py --max-memory 2GB

# Enable streaming mode for large payloads
python ants.py --streaming --max-payload-memory 100MB
```

### Disk I/O Optimization
```yaml
logging:
  async_write: true
  batch_size: 100
  flush_interval: 5  # seconds
  compression: true
```

## 🚨 Troubleshooting Capture

### Common Issues

#### No Traffic Captured
```bash
# Check proxy configuration
netstat -an | grep :8080

# Verify proxy settings
curl -v --proxy http://127.0.0.1:8080 http://httpbin.org/ip

# Test with simple HTTP request
python scripts/test_capture.py
```

#### HTTPS Certificate Errors
```bash
# Verify certificate installation
python scripts/verify_certificate.py

# Regenerate certificate
rm -rf ~/.mitmproxy/
python ants.py --generate-certs
```

#### Performance Issues
```bash
# Monitor resource usage
python ants.py --monitor-performance

# Enable performance profiling
python ants.py --profile --profile-output profile.stats
```

### Debug Mode
```bash
# Enable detailed debugging
python ants.py --debug --trace-requests

# Log all network operations
python ants.py --debug-network

# Save debug information
python ants.py --debug --debug-file debug.log
```

## 📈 Capture Metrics

### Built-in Metrics
- Requests per second
- Response times
- Payload sizes
- Error rates
- Rule matches

### Custom Metrics
```python
# scripts/custom_metrics.py
def custom_metric_collector(flow):
    """Collect custom metrics from traffic"""
    return {
        "custom_header_count": len([h for h in flow.request.headers if h.startswith("X-")]),
        "response_compression": flow.response.headers.get("Content-Encoding", "none")
    }
```

## 🔐 Security Considerations

### Certificate Security
- Rotate certificates regularly
- Use separate certificates for different environments
- Monitor certificate usage and revocation

### Access Control
```yaml
security:
  client_certificates: true
  allowed_clients:
    - "192.168.1.0/24"
  rate_limiting:
    requests_per_minute: 1000
```

### Audit Trail
```yaml
logging:
  audit:
    enabled: true
    include_payloads: false  # For privacy
    retention_days: 90
```

---

*Remember to disable proxy settings when not actively capturing to avoid disrupting normal network operations.*