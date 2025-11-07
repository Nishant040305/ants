# HTTP Packet Analyzer - ANTS Project

A real-time HTTP packet analyzer that uses both pattern matching and LLM-based analysis to detect sensitive data exposure and security vulnerabilities.

## Project Structure

### Prompts
LLM prompts are organized in the `prompts/` directory using `.prompt.md` extension:
- `prompts/security_analysis.prompt.md` - Main security analysis prompt for Gemini API

### Dependencies
All required dependencies should be installed:
```bash
pip install -r requirements.txt
```

## Development & Testing

### Unit Tests

Each module includes comprehensive unit tests with sample toy data that run without requiring admin privileges or external dependencies:

#### Run All Tests
```bash
# From the ants/ directory
python run_tests.py
```

#### Run Individual Module Tests
```bash
# Pattern analyzer - regex-based security rule detection
python -m rules.pattern_analyzer

# Packet capture - Real HTTP traffic capture (requires admin privileges)
python -m data_extraction.pyshark_packet_capture

# LLM analyzer - Gemini API integration (mock analysis when no API key)
python -m model.llm_analyzer

# Database manager - SQLite event storage
python -m src.database

# Main application - integrated workflow testing
python -m src.main --test
```

### Test Features
- 🧪 **Mock Data**: All tests use sample toy data, no admin privileges required
- 🔒 **Safe Testing**: No real network packets captured during testing
- 📊 **Comprehensive Coverage**: Tests cover pattern matching, LLM analysis, database operations, and packet processing
- 🚀 **Quick Feedback**: Fast test execution for development workflow