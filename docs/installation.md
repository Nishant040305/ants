# Installation Guide

Complete installation instructions for ANTS on different platforms.

## 🎯 System Requirements

### Minimum Requirements
- **Python**: 3.8 or higher
- **RAM**: 4GB minimum, 8GB recommended
- **Storage**: 2GB free space
- **Network**: Internet connection for AI analysis
- **OS**: Windows 10+, macOS 10.15+, Ubuntu 18.04+

### Administrative Privileges
- **Windows**: Administrator rights for proxy configuration
- **Linux/Mac**: Sudo access for network interface manipulation

## 📦 Installation Methods

### Method 1: Git Clone (Recommended)
```bash
# Clone repository
git clone https://github.com/Nishant040305/ants.git
cd ants

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows:
.venv\Scripts\activate
# Linux/Mac:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Method 2: Download ZIP
```bash
# Download and extract ZIP from GitHub
# Navigate to extracted folder
cd ants-main

# Create virtual environment and install as above
python -m venv .venv
# ... continue with activation and pip install
```

## 🔧 Dependencies

### Core Dependencies
```bash
# Network analysis
mitmproxy>=10.0.0
pyshark>=0.6

# AI analysis
google-generativeai>=0.3.0
openai>=1.0.0  # Optional
anthropic>=0.7.0  # Optional

# Data processing
pandas>=1.5.0
numpy>=1.21.0
sqlite3  # Built-in

# Utilities
python-dotenv>=1.0.0
requests>=2.28.0
colorama>=0.4.6  # Windows color support
```

### Development Dependencies (Optional)
```bash
# Testing
pytest>=7.0.0
pytest-cov>=4.0.0

# Code quality
black>=23.0.0
flake8>=6.0.0
mypy>=1.0.0

# Install development dependencies
pip install -r requirements-dev.txt
```

## 🌍 Platform-Specific Setup

### Windows Setup
```powershell
# Install Python from python.org or Microsoft Store
# Verify installation
python --version
pip --version

# Clone and setup (in PowerShell)
git clone https://github.com/Nishant040305/ants.git
cd ants
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

# Verify installation
python ants.py --version
```

### Linux (Ubuntu/Debian) Setup
```bash
# Update system packages
sudo apt update
sudo apt install python3 python3-pip python3-venv git

# Install system dependencies for packet capture
sudo apt install tshark wireshark-common

# Clone and setup
git clone https://github.com/Nishant040305/ants.git
cd ants
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Add user to wireshark group (for packet capture)
sudo usermod -a -G wireshark $USER
# Log out and back in for group changes to take effect
```

### macOS Setup
```bash
# Install Homebrew if not present
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python and dependencies
brew install python git
brew install wireshark  # For packet capture

# Clone and setup
git clone https://github.com/Nishant040305/ants.git
cd ants
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 🔑 Environment Configuration

### 1. Create Environment File
```bash
# Copy template
cp .env.example .env

# Edit .env file
nano .env  # Linux/Mac
notepad .env  # Windows
```

### 2. Required Environment Variables
```bash
# .env file contents
GOOGLE_API_KEY=your_gemini_api_key_here
OPENAI_API_KEY=your_openai_key_here  # Optional
ANTHROPIC_API_KEY=your_claude_key_here  # Optional

# Network configuration
MITM_PORT=8080
MITM_HOST=127.0.0.1

# Logging configuration
LOG_LEVEL=INFO
LOG_DIR=logs

# Analysis configuration
MAX_PAYLOAD_SIZE=1048576  # 1MB
ANALYSIS_TIMEOUT=300  # 5 minutes
```

### 3. API Key Setup

#### Google Gemini API
1. Visit [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Create new API key
3. Add to `.env` as `GOOGLE_API_KEY=your_key_here`

#### OpenAI API (Optional)
1. Visit [OpenAI Platform](https://platform.openai.com/api-keys)
2. Create new secret key
3. Add to `.env` as `OPENAI_API_KEY=your_key_here`

#### Anthropic Claude API (Optional)
1. Visit [Anthropic Console](https://console.anthropic.com/keys)
2. Create new key
3. Add to `.env` as `ANTHROPIC_API_KEY=your_key_here`

## 🧪 Verify Installation

### Basic Verification
```bash
# Check ANTS version
python ants.py --version

# Check dependencies
python -c "import mitmproxy, google.generativeai; print('Dependencies OK')"

# Run self-test
python ants.py --test
```

### Network Capabilities Test
```bash
# Test proxy setup (requires admin/sudo)
python scripts/proxy_test.py

# Test packet capture (requires admin/sudo)
python scripts/capture_test.py

# Test AI analysis (requires API keys)
python scripts/analysis_test.py
```

## 🔒 Security Considerations

### Certificate Installation
ANTS uses MITM proxy for HTTPS analysis. Install the certificate:

#### Windows
```cmd
# Auto-install (run as administrator)
scripts\install_certificate.bat

# Manual install
certutil -addstore -enterprise -f "Root" "%USERPROFILE%\.mitmproxy\mitmproxy-ca-cert.cer"
```

#### Linux
```bash
# Auto-install
sudo scripts/install_certificate.sh

# Manual install
sudo cp ~/.mitmproxy/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy.crt
sudo update-ca-certificates
```

#### macOS
```bash
# Install to system keychain
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/.mitmproxy/mitmproxy-ca-cert.pem
```

### Firewall Configuration
```bash
# Windows (run as administrator)
netsh advfirewall firewall add rule name="ANTS MITM" dir=in action=allow protocol=TCP localport=8080

# Linux (ufw)
sudo ufw allow 8080/tcp

# macOS
# Use System Preferences > Security & Privacy > Firewall
```

## 🚨 Troubleshooting Installation

### Common Issues

#### Python Version Issues
```bash
# Check Python version
python --version  # Should be 3.8+

# If multiple Python versions, use specific version
python3.9 -m venv .venv  # Use specific version
```

#### Permission Errors
```bash
# Windows: Run PowerShell as Administrator
# Linux/Mac: Use sudo for system operations
sudo python scripts/network_setup.py
```

#### Dependency Conflicts
```bash
# Clear pip cache
pip cache purge

# Reinstall dependencies
pip uninstall -r requirements.txt -y
pip install -r requirements.txt
```

#### Certificate Issues
```bash
# Remove old certificates
scripts/remove_certificates.sh  # Linux/Mac
scripts\remove_certificates.bat  # Windows

# Reinstall certificates
scripts/install_certificate.sh  # Linux/Mac
scripts\install_certificate.bat  # Windows
```

### Getting Help
- Check [Troubleshooting Guide](troubleshooting.md)
- Review [FAQ](faq.md)
- Open GitHub issue with:
  - OS version
  - Python version
  - Error messages
  - Installation method used

## ✅ Post-Installation

After successful installation:
1. **[Quick Start Guide](getting-started.md)** - Basic usage
2. **[Configuration Guide](configuration.md)** - Customize settings
3. **[Traffic Capture Guide](traffic-capture.md)** - Start capturing traffic

---

*Installation typically takes 10-15 minutes including dependency download.*