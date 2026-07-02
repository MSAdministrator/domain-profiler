# Domain Profiler

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

A comprehensive Python CLI tool and package for domain analysis and profiling. Gather detailed information about domains including DNS records, website characteristics, domain registration data, and security indicators.

## Features

### 🔍 DNS Analysis
- **Comprehensive DNS Records**: Query all standard DNS record types (A, AAAA, MX, TXT, NS, SOA, CNAME, etc.)
- **IP Resolution**: Get all IP addresses associated with a domain
- **Reverse DNS Lookup**: Resolve IP addresses back to hostnames
- **Domain Aliases**: Discover domain aliases and CNAME records

### 🌐 Website Analysis (Live Mode)
- **Site Availability**: Check if website is accessible
- **Security Indicators**: Detect potential phishing characteristics
- **Domain Registration**: Age, registration length, and WHOIS data
- **Redirects**: Track HTTP redirects and URL changes
- **Favicon Analysis**: Extract and hash favicons for fingerprinting
- **Content Analysis**: Form detection, popup detection, and more

### 🛡️ Security Features
- Suspicious URL pattern detection
- Abnormal port usage detection
- Subdomain enumeration
- File extension analysis

### 🔐 DNS-Layer Security Analysis (`--security`)
- **DNSSEC validation** — verifies the full chain of trust (DNSKEY self-signature
  + parent DS match), distinguishing `secure` / `bogus` / `insecure`, and flags
  weak signing algorithms
- **CAA policy analysis** — reports which CAs may issue certificates, climbing the
  DNS tree as a CA would, and flags "any CA may issue" / missing iodef contact
- **RDAP registration data** — structured registrar, registration/expiry dates,
  EPP status codes, nameservers, and DNSSEC delegation

## Installation

### From PyPI (Recommended)
```bash
pip install domain-profiler
```

### From Source
```bash
git clone https://github.com/sublime-security/domain-profiler.git
cd domain-profiler
pip install -e .
```

### Using uv (Fast Python Package Manager)
```bash
uv add domain-profiler
```

## Quick Start

### Basic Domain Analysis
```bash
# DNS-only analysis (fast)
domain-profiler run example.com

# Full analysis including website profiling
domain-profiler run example.com --live

# Include DNS-layer security analysis (DNSSEC, CAA, RDAP)
domain-profiler run example.com --security

# Security analysis only
domain-profiler security example.com
```

### Python API Usage
```python
from domain_profiler import Profiler

# Create profiler instance
profiler = Profiler()

# DNS analysis only
dns_data = profiler.run("example.com")

# Full analysis with website profiling
full_data = profiler.run("example.com", live=True)

# DNS-layer security analysis (DNSSEC / CAA / RDAP)
security_data = profiler.run("example.com", security=True)
# ...or standalone:
security_only = profiler.security("example.com")

print(full_data)
```

## Usage

### Command Line Interface

The CLI is built using Google Fire, providing an intuitive interface:

```bash
domain-profiler run DOMAIN [--live] [--email] [--security]
```

#### Parameters

- `DOMAIN`: The domain to analyze (required)
- `--live`: Enable website analysis in addition to DNS (optional, default: False)
- `--email`: Enable email-authentication analysis — SPF/DKIM/DMARC/BIMI/MX (optional, default: False)
- `--security`: Enable DNS-layer security analysis — DNSSEC/CAA/RDAP (optional, default: False)

#### Examples

```bash
# Basic DNS analysis
domain-profiler run google.com

# Full analysis with website profiling
domain-profiler run https://example.com --live

# Analysis with IP address
domain-profiler run 8.8.8.8
```

### Output Format

The tool returns structured JSON data containing:

#### DNS Analysis Output
```json
{
  "domain": "example.com",
  "aliases": ["www.example.com"],
  "ips": {
    "93.184.216.34": {
      "host": "example.com",
      "fqdn": "example.com",
      "reverse": {...}
    }
  },
  "dns": {
    "A": ["93.184.216.34"],
    "MX": ["0 ."],
    "NS": ["a.iana-servers.net.", "b.iana-servers.net."],
    "TXT": ["v=spf1 -all"]
  }
}
```

#### Live Analysis Additional Data
When using `--live` flag, additional website data is included:
- URL parsing details (scheme, netloc, path, etc.)
- Site availability status
- HTTPS availability
- Security indicators
- Domain registration information
- Favicon hashes
- Page title

## Dependencies

The tool uses several robust Python libraries:

- **dnspython**: DNS resolution and analysis
- **requests-html**: Website content analysis with JavaScript support
- **beautifulsoup4**: HTML parsing and analysis
- **python-whois**: Domain registration information
- **fire**: Command-line interface generation
- **pendulum**: Date/time handling
- **mmh3**: Favicon hashing

## Development

### Setup Development Environment

```bash
# Clone the repository
git clone https://github.com/sublime-security/domain-profiler.git
cd domain-profiler

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install in development mode
pip install -e .
```

### Project Structure

```
domain-profiler/
├── src/domain_profiler/
│   ├── __init__.py
│   ├── __main__.py          # CLI entry point
│   ├── profiler.py          # Main profiler class
│   ├── dns.py              # DNS analysis functionality
│   ├── site.py             # Website analysis functionality
│   ├── base.py             # Base classes and utilities
│   └── logger.py           # Logging configuration
├── pyproject.toml          # Project configuration
├── README.md
└── uv.lock                # Dependency lock file
```

### Running Tests

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run all tests
pytest

# Run tests with coverage
pytest --cov=domain_profiler --cov-report=html

# Run tests in parallel
pytest -n auto

# Run specific test categories
pytest -m unit          # Unit tests only
pytest -m integration   # Integration tests only
pytest -m "not slow"    # Skip slow tests

# Run specific test files
pytest tests/test_profiler.py
pytest tests/test_dns.py
pytest tests/test_site.py

# Run with verbose output
pytest -v

# Generate coverage report
pytest --cov=domain_profiler --cov-report=term-missing
```

### Test Structure

The test suite includes comprehensive coverage of all modules:

- **`tests/test_profiler.py`**: Main profiler functionality, CLI integration
- **`tests/test_dns.py`**: DNS resolution, record queries, IP lookups
- **`tests/test_site.py`**: Website analysis, security indicators, WHOIS data
- **`tests/test_cli.py`**: Command-line interface, Fire integration
- **`tests/test_base.py`**: Base classes, inheritance, extensions
- **`tests/test_logger.py`**: Logging system, formatters, metaclass

### Testing Features

- **Comprehensive Mocking**: All external dependencies (DNS, HTTP, WHOIS) are mocked
- **Edge Case Coverage**: Error handling, timeouts, invalid inputs
- **Parametrized Tests**: Multiple input variations and scenarios
- **Integration Tests**: End-to-end functionality testing
- **Coverage Reporting**: HTML and terminal coverage reports
- **Parallel Execution**: Fast test runs with pytest-xdist

## Use Cases

### Security Research
- Analyze suspicious domains for phishing indicators
- Investigate domain infrastructure and hosting
- Track domain reputation and history

### Infrastructure Monitoring
- Monitor DNS configuration changes
- Verify domain accessibility and redirects
- Check SSL/TLS certificate deployment

### Competitive Analysis
- Analyze competitor domain infrastructure
- Track website technology changes
- Monitor domain registration patterns

## Performance Considerations

- **DNS-only analysis**: Fast, typically completes in 1-3 seconds
- **Live analysis**: Slower due to website requests, may take 5-15 seconds
- **Timeout handling**: Built-in timeouts prevent hanging on unresponsive sites
- **Error resilience**: Gracefully handles network errors and invalid domains

## Error Handling

The tool is designed to be resilient:
- Network timeouts are handled gracefully
- Invalid domains return partial data where possible
- HTTPS/HTTP fallback for website analysis
- Comprehensive logging for debugging

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Testing

The project includes a comprehensive test suite with **149 tests** and **85% code coverage**.

### Quick Testing

```bash
# Run all tests
make test

# Run tests with coverage report
make test-coverage

# Run tests in parallel (faster)
make test-fast
```

### Test Results Summary

- ✅ **149 tests passing**
- 📊 **85% overall coverage**
- 🎯 **100% coverage** on core modules (CLI, base, logger, profiler)
- 🔧 **Comprehensive mocking** of all external dependencies
- 🚀 **No real network calls** during testing

## Changelog

### v0.1.0
- Initial release
- DNS analysis functionality
- Website profiling with live mode
- CLI interface with Fire
- Comprehensive domain reporting
- Full test suite with 149 tests and 85% coverage

## Support

- **Issues**: [GitHub Issues](https://github.com/sublime-security/domain-profiler/issues)
- **Documentation**: This README and inline code documentation
- **Python Version**: Requires Python 3.11+

## Security Notice

This tool is intended for legitimate security research, infrastructure monitoring, and educational purposes. Please ensure you have proper authorization before analyzing domains you do not own or control.
