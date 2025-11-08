# Configuration Guide

Complete guide to configuring ANTS for your environment and use cases.

## 🔧 Configuration Files

### Environment Configuration (.env)
```bash
# API Keys
GOOGLE_API_KEY=your_gemini_api_key_here
OPENAI_API_KEY=your_openai_key_here          # Optional
ANTHROPIC_API_KEY=your_claude_key_here       # Optional

# Network Settings
MITM_PORT=8080
MITM_HOST=127.0.0.1
MITM_TRANSPARENT=false

# Logging Configuration
LOG_LEVEL=INFO                               # DEBUG, INFO, WARNING, ERROR
LOG_DIR=logs
LOG_MAX_SIZE=10485760                        # 10MB per file
LOG_BACKUP_COUNT=5

# Analysis Settings
MAX_PAYLOAD_SIZE=1048576                     # 1MB
ANALYSIS_TIMEOUT=300                         # 5 minutes
AI_MODEL=gemini-pro
ENABLE_AI_ANALYSIS=true

# Performance Settings
MAX_CONCURRENT_REQUESTS=10
CACHE_SIZE=1000
THREAD_POOL_SIZE=4

# Security Settings
ALLOW_INSECURE_CERTS=false
TRUSTED_DOMAINS=microsoft.com,google.com,github.com
BLOCKED_DOMAINS=malicious-site.com
```

### Application Configuration (config.yaml)
```yaml
# Network Configuration
network:
  proxy:
    host: "127.0.0.1"
    port: 8080
    transparent: false
  certificates:
    auto_install: true
    cert_path: "~/.mitmproxy/mitmproxy-ca-cert.pem"

# Analysis Configuration
analysis:
  ai:
    enabled: true
    model: "gemini-pro"
    timeout: 300
    max_retries: 3
  rules:
    enabled_rules:
      - auth_token_leak
      - xss_payload  
      - c2_indicators
      - large_upload
    custom_rules_path: "rules/custom/"
  
# Logging Configuration
logging:
  level: "INFO"
  format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
  files:
    summary: "logs/summary-{date}.jsonl"
    alerts: "logs/alerts-{date}.jsonl"
    full: "logs/full-{date}.jsonl"
  rotation:
    max_size: "10MB"
    backup_count: 5

# Output Configuration
output:
  formats: ["json", "csv"]
  compression: true
  real_time: true
  
# Performance Configuration
performance:
  max_concurrent: 10
  cache_size: 1000
  thread_pool: 4
  memory_limit: "1GB"
```

## 🎯 Configuration Profiles

### Development Profile
```yaml
# config/development.yaml
analysis:
  ai:
    enabled: false  # Disable AI to save API costs
logging:
  level: "DEBUG"
  real_time: true
performance:
  max_concurrent: 5  # Lower resource usage
```

### Production Profile  
```yaml
# config/production.yaml
analysis:
  ai:
    enabled: true
    model: "gemini-1.5-pro"  # More capable model
logging:
  level: "WARNING"
  compression: true
performance:
  max_concurrent: 20
  memory_limit: "4GB"
security:
  strict_certificates: true
```

### High-Security Profile
```yaml
# config/high-security.yaml
analysis:
  rules:
    enabled_rules: "all"
    sensitivity: "high"
logging:
  level: "INFO"
  audit_trail: true
security:
  allow_insecure_certs: false
  strict_validation: true
  blocked_domains: 
    - "suspicious-domain.com"
    - "known-malware-host.com"
```

## 🔑 API Configuration

### Google Gemini Setup
```bash
# 1. Get API key from Google AI Studio
# 2. Add to .env file
GOOGLE_API_KEY=your_key_here

# 3. Configure model preferences
AI_MODEL=gemini-pro                    # Standard model
# AI_MODEL=gemini-1.5-pro             # Advanced model (higher cost)
```

### OpenAI Setup (Optional)
```bash
# 1. Get API key from OpenAI Platform
# 2. Add to .env file
OPENAI_API_KEY=your_key_here

# 3. Configure model
AI_MODEL=gpt-4                         # Premium model
# AI_MODEL=gpt-3.5-turbo              # Cost-effective option
```

### Anthropic Claude Setup (Optional)
```bash
# 1. Get API key from Anthropic Console
# 2. Add to .env file
ANTHROPIC_API_KEY=your_key_here

# 3. Configure model
AI_MODEL=claude-3-opus-20240229        # Most capable
# AI_MODEL=claude-3-sonnet-20240229    # Balanced option
```

## 🛡️ Security Rules Configuration

### Built-in Rules
```yaml
# Enable/disable specific rules
security_rules:
  auth_token_leak:
    enabled: true
    sensitivity: "high"
    headers: ["Authorization", "APIKey", "Bearer"]
  
  large_upload:
    enabled: true
    threshold: 500000  # 500KB
    
  xss_payload:
    enabled: true
    patterns: ["<script", "javascript:", "onload="]
    
  c2_indicators:
    enabled: true
    paths: ["/api/v1/ping", "/update", "/beacon"]
```

### Custom Rules Directory
```bash
# Create custom rules directory
mkdir rules/custom/

# Add custom rule file
# rules/custom/my_rules.py
def custom_rule_example(req):
    """Detect custom suspicious patterns"""
    return "suspicious-pattern" in req.path.lower()

CUSTOM_RULES = [
    ("custom_suspicious", custom_rule_example),
]
```

## 📊 Logging Configuration

### Log Levels
```python
# DEBUG: Verbose debugging information
# INFO:  General operational messages  
# WARNING: Important warnings
# ERROR: Error conditions
# CRITICAL: Critical errors only
```

### Log Formats
```yaml
logging:
  formats:
    console: "%(levelname)s: %(message)s"
    file: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    json: true  # Structured JSON logging
```

### Log Rotation
```yaml
logging:
  rotation:
    when: "midnight"      # Daily rotation
    interval: 1
    backup_count: 30      # Keep 30 days
    max_size: "100MB"     # Size-based rotation
```

## ⚡ Performance Tuning

### Memory Management
```yaml
performance:
  memory:
    max_heap: "2GB"
    gc_threshold: 100000
    payload_cache: "100MB"
```

### Concurrency Settings
```yaml
performance:
  concurrency:
    worker_threads: 4
    max_queue_size: 1000
    request_timeout: 30
```

### Caching Configuration
```yaml
performance:
  cache:
    rule_cache_size: 10000
    payload_cache_ttl: 3600  # 1 hour
    dns_cache_ttl: 300       # 5 minutes
```

## 🌐 Network Configuration

### Proxy Settings
```yaml
network:
  proxy:
    host: "0.0.0.0"          # Listen on all interfaces
    port: 8080
    ssl_insecure: false      # Strict SSL validation
    upstream_cert: true      # Verify upstream certificates
```

### Certificate Management
```yaml
network:
  certificates:
    ca_cert: "~/.mitmproxy/mitmproxy-ca-cert.pem"
    ca_key: "~/.mitmproxy/mitmproxy-ca-cert-key.pem"
    cert_store: "system"     # or "user"
    auto_install: true
```

### Traffic Filtering
```yaml
network:
  filtering:
    ignore_hosts:
      - "localhost"
      - "127.0.0.1"
    ignore_extensions:
      - ".jpg"
      - ".png"
      - ".css"
    max_request_size: "10MB"
```

## 🔍 Advanced Configuration

### Database Settings
```yaml
database:
  type: "sqlite"
  path: "logs/events.db"
  connection_pool: 5
  vacuum_interval: "daily"
```

### Integration Settings
```yaml
integrations:
  webhook:
    enabled: false
    url: "https://your-webhook-endpoint.com"
    events: ["high_severity", "critical"]
  
  syslog:
    enabled: false
    host: "syslog-server.example.com"
    port: 514
```

## 📝 Configuration Validation

### Validate Configuration
```bash
# Check configuration syntax
python ants.py --validate-config

# Test configuration with dry run
python ants.py --dry-run

# Show current configuration
python ants.py --show-config
```

### Configuration Templates
```bash
# Generate configuration template
python ants.py --generate-config > config.yaml

# Generate environment template
python ants.py --generate-env > .env
```

## 🚨 Troubleshooting Configuration

### Common Issues
```bash
# Configuration file not found
export ANTS_CONFIG=config/production.yaml

# Permission issues
chmod 600 .env  # Secure environment file

# Invalid YAML syntax
python -c "import yaml; yaml.safe_load(open('config.yaml'))"

# Missing API keys
python scripts/test_api_keys.py
```

### Debug Configuration
```yaml
# Enable configuration debugging
debug:
  config_validation: true
  show_loaded_config: true
  trace_config_loading: true
```

---

*Configuration changes take effect on next restart unless noted otherwise.*