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

### 🔐 Security Analysis (`--security`)
- **DNSSEC validation** — verifies the full chain of trust (DNSKEY self-signature
  + parent DS match), distinguishing `secure` / `bogus` / `insecure`, and flags
  weak signing algorithms
- **CAA policy analysis** — reports which CAs may issue certificates, climbing the
  DNS tree as a CA would, and flags "any CA may issue" / missing iodef contact
- **RDAP registration data** — structured registrar, registration/expiry dates,
  EPP status codes, nameservers, and DNSSEC delegation
- **TLS certificate inspection** — issuer, validity window, SAN coverage, key
  strength; flags self-signed, expired, very-fresh, SAN-mismatch, and
  untrusted-chain certificates
- **Subdomain-takeover & wildcard detection** — detects wildcard DNS (baseline)
  and dangling CNAMEs pointing at unprovisioned takeover-prone providers

### 📧 Email Authentication (`--email`)
- **SPF** — record lookup with `include`/`redirect` tree expansion and a flattened
  view of authorized senders
- **DKIM** — probes common (and any user-supplied) selectors for signing keys
- **DMARC** — policy, alignment, and reporting-address parsing
- **BIMI** — brand-indicator record discovery
- **MX** — mail-exchanger records backing the domain

### 🎭 Typosquat / Homoglyph Detection (`typosquat`)
- Scores a candidate domain against a known **brand** — edit-distance similarity,
  homoglyph normalization (Cyrillic/Greek/digit look-alikes), and IDN/punycode
  decoding to catch homograph attacks

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

# Include email-authentication analysis (SPF, DKIM, DMARC, BIMI, MX)
domain-profiler run example.com --email

# Include security analysis (DNSSEC, CAA, RDAP, TLS, takeover)
domain-profiler run example.com --security

# Security analysis only
domain-profiler security example.com

# WHOIS registration analysis only
domain-profiler whois example.com

# Email-authentication analysis only
domain-profiler email example.com

# Probe a specific DKIM selector first
domain-profiler email example.com --dkim-selector google

# Inspect just the TLS certificate
domain-profiler tls example.com

# Check for wildcard DNS / dangling-CNAME takeover risk
domain-profiler takeover example.com

# Score a candidate domain against a brand for typosquatting
domain-profiler typosquat paypa1.com --brand paypal.com
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

# Email-authentication analysis (SPF / DKIM / DMARC / BIMI / MX)
email_data = profiler.run("example.com", email=True)
# ...or standalone:
email_only = profiler.email("example.com")

# Security analysis (DNSSEC / CAA / RDAP / TLS / subdomain-takeover / WHOIS)
security_data = profiler.run("example.com", security=True)
# ...or standalone:
security_only = profiler.security("example.com")
whois_only = profiler.whois("example.com")

print(full_data)
```

## Usage

### Command Line Interface

The CLI is built using Google Fire, providing an intuitive interface:

```bash
domain-profiler run DOMAIN [--live] [--email] [--dkim-selector SELECTOR] [--security]

domain-profiler whois DOMAIN
```

#### Parameters

- `DOMAIN`: The domain to analyze (required)
- `--live`: Enable website analysis in addition to DNS (optional, default: False)
- `--email`: Enable email-authentication analysis — SPF/DKIM/DMARC/BIMI/MX (optional, default: False)
- `--dkim-selector`: Extra DKIM selector to probe first (optional)
- `--security`: Enable security analysis — DNSSEC/CAA/RDAP/TLS/subdomain-takeover/WHOIS (optional, default: False)

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

#### Security Analysis Additional Data
When using `--security` flag (or the `security` command), the `security` object includes:
- `dnssec`
- `caa`
- `rdap`
- `tls`
- `takeover`
- `whois`

## Dependencies

The tool uses several robust Python libraries:

- **dnspython**: DNS resolution and analysis (including DNSSEC/CAA/email records)
- **cryptography**: TLS certificate parsing and inspection
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
│   ├── dns.py               # DNS analysis functionality
│   ├── site.py              # Website analysis functionality
│   ├── email_auth.py        # SPF/DKIM/DMARC/BIMI/MX analysis
│   ├── dnssec.py            # DNSSEC chain-of-trust validation
│   ├── caa.py               # CAA policy analysis
│   ├── rdap.py              # RDAP registration data
│   ├── tls.py               # TLS certificate inspection
│   ├── takeover.py          # Subdomain-takeover & wildcard detection
│   ├── typosquat.py         # Typosquat / homoglyph detection
│   ├── base.py              # Base classes and utilities
│   └── logger.py            # Logging configuration
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
pytest tests/test_email_auth.py
pytest tests/test_tls.py

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
- **`tests/test_email_auth.py`**: SPF/DKIM/DMARC/BIMI/MX resolution and parsing
- **`tests/test_dnssec.py`**: DNSSEC chain-of-trust validation
- **`tests/test_caa.py`**: CAA policy analysis
- **`tests/test_rdap.py`**: RDAP registration-data parsing
- **`tests/test_tls.py`**: TLS certificate inspection and security flags
- **`tests/test_takeover.py`**: Wildcard DNS and dangling-CNAME detection
- **`tests/test_typosquat.py`**: Typosquat / homoglyph scoring
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

The project includes a comprehensive test suite with **300+ tests** spanning DNS,
website, email-authentication, and security analysis, hardened with mutation testing.

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

- ✅ **300+ tests passing** across 13 test modules
- 🎯 **Dedicated suites** for every analysis module (DNS, site, email, DNSSEC, CAA, RDAP, TLS, takeover, typosquat)
- 🧬 **Mutation-tested** to verify tests actually catch regressions
- 🔧 **Comprehensive mocking** of all external dependencies
- 🚀 **No real network calls** during testing

## Changelog

### Unreleased
- Email-authentication analysis (`--email` / `email`): SPF (with tree expansion and
  flattening), DKIM selector probing, DMARC, BIMI, and MX
- Tier 1 DNS-layer security (`--security` / `security`): DNSSEC chain-of-trust
  validation, CAA policy analysis, and RDAP registration data
- Tier 2 security signals: TLS certificate inspection (`tls`), subdomain-takeover
  and wildcard detection (`takeover`), and typosquat/homoglyph scoring (`typosquat`)
- Test suite expanded to 300+ tests and hardened with mutation testing

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
