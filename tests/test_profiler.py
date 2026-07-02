"""Tests for the main Profiler class."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from urllib.parse import urlparse

from domain_profiler.profiler import Profiler


class TestProfiler:
    """Test cases for the Profiler class."""

    def test_profiler_initialization(self):
        """Test that Profiler can be initialized."""
        profiler = Profiler()
        assert isinstance(profiler, Profiler)

    @patch('domain_profiler.profiler.DNSCheck')
    def test_run_with_domain_no_live(self, mock_dns_check, sample_domain):
        """Test running profiler with domain only (no live analysis)."""
        # Setup mocks
        mock_dns_instance = Mock()
        mock_dns_check.return_value = mock_dns_instance
        mock_dns_instance.get_report.return_value = {
            'domain': sample_domain,
            'ips': {'93.184.216.34': {}},
            'dns': {'A': ['93.184.216.34']}
        }

        profiler = Profiler()
        result = profiler.run(sample_domain, live=False)

        # Assertions
        mock_dns_check.assert_called_once()
        mock_dns_instance.get_report.assert_called_once_with(domain=sample_domain)
        assert result['domain'] == sample_domain
        assert 'ips' in result
        assert 'dns' in result

    @patch('domain_profiler.profiler.Url')
    @patch('domain_profiler.profiler.DNSCheck')
    def test_run_with_domain_live_mode(self, mock_dns_check, mock_url, sample_url):
        """Test running profiler with live analysis enabled."""
        # Setup mocks
        mock_dns_instance = Mock()
        mock_dns_check.return_value = mock_dns_instance
        mock_dns_instance.get_report.return_value = {
            'domain': 'example.com',
            'ips': {'93.184.216.34': {}},
            'dns': {'A': ['93.184.216.34']}
        }

        mock_url_instance = Mock()
        mock_url.return_value = mock_url_instance
        mock_url_instance.to_json.return_value = {
            'url': sample_url,
            'is_alive': True,
            'title': 'Example Domain'
        }

        profiler = Profiler()
        result = profiler.run(sample_url, live=True)

        # Assertions
        mock_dns_check.assert_called_once()
        # With the updated logic, URL analysis constructs https:// + netloc
        mock_url.assert_called_once_with(url='https://example.com')
        mock_url_instance.to_json.assert_called_once()
        
        assert result['domain'] == 'example.com'
        assert result['url'] == sample_url
        assert result['is_alive'] is True

    @patch('domain_profiler.profiler.DNSCheck')
    def test_run_with_url_extracts_netloc(self, mock_dns_check, sample_url):
        """Test that URLs have their netloc extracted for DNS analysis."""
        mock_dns_instance = Mock()
        mock_dns_check.return_value = mock_dns_instance
        mock_dns_instance.get_report.return_value = {'domain': 'example.com'}

        profiler = Profiler()
        profiler.run(sample_url, live=False)

        # Should extract netloc from URL
        expected_domain = urlparse(sample_url).netloc
        mock_dns_instance.get_report.assert_called_once_with(domain=expected_domain)

    @patch('domain_profiler.profiler.DNSCheck')
    def test_run_with_plain_domain(self, mock_dns_check, sample_domain):
        """Test running with plain domain (no scheme)."""
        mock_dns_instance = Mock()
        mock_dns_check.return_value = mock_dns_instance
        mock_dns_instance.get_report.return_value = {'domain': sample_domain}

        profiler = Profiler()
        profiler.run(sample_domain, live=False)

        # Should use domain as-is
        mock_dns_instance.get_report.assert_called_once_with(domain=sample_domain)

    @patch('domain_profiler.profiler.Url')
    @patch('domain_profiler.profiler.DNSCheck')
    def test_run_live_mode_updates_response(self, mock_dns_check, mock_url, sample_domain):
        """Test that live mode properly updates the response with site data."""
        # Setup DNS mock
        dns_response = {'domain': sample_domain, 'dns': {'A': ['93.184.216.34']}}
        mock_dns_instance = Mock()
        mock_dns_check.return_value = mock_dns_instance
        mock_dns_instance.get_report.return_value = dns_response

        # Setup URL mock
        site_data = {
            'url': sample_domain,
            'is_alive': True,
            'has_https': True,
            'title': 'Test Site'
        }
        mock_url_instance = Mock()
        mock_url.return_value = mock_url_instance
        mock_url_instance.to_json.return_value = site_data

        profiler = Profiler()
        result = profiler.run(sample_domain, live=True)

        # Should contain both DNS and site data
        assert result['domain'] == sample_domain
        assert result['dns'] == {'A': ['93.184.216.34']}
        assert result['url'] == sample_domain
        assert result['is_alive'] is True
        assert result['has_https'] is True

    @patch('domain_profiler.profiler.DNSCheck')
    def test_run_handles_dns_errors_gracefully(self, mock_dns_check, sample_domain):
        """Test that DNS errors are handled gracefully."""
        mock_dns_instance = Mock()
        mock_dns_check.return_value = mock_dns_instance
        mock_dns_instance.get_report.side_effect = Exception("DNS lookup failed")

        profiler = Profiler()
        
        # Should not raise exception
        with pytest.raises(Exception):
            profiler.run(sample_domain, live=False)

    def test_run_with_empty_domain(self):
        """Test running with empty domain."""
        profiler = Profiler()
        
        with patch('domain_profiler.profiler.DNSCheck') as mock_dns_check:
            mock_dns_instance = Mock()
            mock_dns_check.return_value = mock_dns_instance
            mock_dns_instance.get_report.return_value = {'domain': ''}
            
            result = profiler.run('', live=False)
            mock_dns_instance.get_report.assert_called_once_with(domain='')

    @patch('domain_profiler.profiler.Url')
    @patch('domain_profiler.profiler.DNSCheck')
    def test_run_live_mode_with_site_error(self, mock_dns_check, mock_url, sample_domain):
        """Test live mode when site analysis fails."""
        # DNS succeeds
        mock_dns_instance = Mock()
        mock_dns_check.return_value = mock_dns_instance
        mock_dns_instance.get_report.return_value = {'domain': sample_domain}

        # Site analysis fails
        mock_url.side_effect = Exception("Site analysis failed")

        profiler = Profiler()
        
        # Should handle site analysis errors
        with pytest.raises(Exception):
            profiler.run(sample_domain, live=True)

    @patch('domain_profiler.profiler.EmailAuth')
    @patch('domain_profiler.profiler.DNSCheck')
    def test_run_with_email_analysis(self, mock_dns_check, mock_email_auth, sample_domain):
        """Test that email=True attaches an email_auth section."""
        mock_dns_instance = Mock()
        mock_dns_check.return_value = mock_dns_instance
        mock_dns_instance.get_report.return_value = {'domain': sample_domain}

        mock_email_instance = Mock()
        mock_email_auth.return_value = mock_email_instance
        mock_email_instance.get_report.return_value = {'spf': None, 'dmarc': None}

        profiler = Profiler()
        result = profiler.run(sample_domain, email=True)

        mock_email_instance.get_report.assert_called_once_with(
            domain=sample_domain, dkim_selector=None
        )
        assert result['email_auth'] == {'spf': None, 'dmarc': None}

    @patch('domain_profiler.profiler.EmailAuth')
    @patch('domain_profiler.profiler.DNSCheck')
    def test_run_positional_dkim_selector_still_binds(
        self, mock_dns_check, mock_email_auth, sample_domain
    ):
        """dkim_selector remains the 4th positional arg (backward compatible)."""
        mock_dns_check.return_value.get_report.return_value = {'domain': sample_domain}
        mock_email_auth.return_value.get_report.return_value = {}

        profiler = Profiler()
        # Legacy positional call: run(domain, live, email, dkim_selector)
        profiler.run(sample_domain, False, True, "s1")

        mock_email_auth.return_value.get_report.assert_called_once_with(
            domain=sample_domain, dkim_selector="s1"
        )

    @patch('domain_profiler.profiler.RDAP')
    @patch('domain_profiler.profiler.CAA')
    @patch('domain_profiler.profiler.DNSSEC')
    @patch('domain_profiler.profiler.DNSCheck')
    def test_run_with_security_analysis(
        self, mock_dns_check, mock_dnssec, mock_caa, mock_rdap, sample_domain
    ):
        """Test that security=True attaches dnssec/caa/rdap sections."""
        mock_dns_instance = Mock()
        mock_dns_check.return_value = mock_dns_instance
        mock_dns_instance.get_report.return_value = {'domain': sample_domain}

        mock_dnssec.return_value.validate.return_value = {'status': 'secure'}
        mock_caa.return_value.analyze.return_value = {'present': True}
        mock_rdap.return_value.report.return_value = {'registrar': 'X'}

        profiler = Profiler()
        result = profiler.run(sample_domain, security=True)

        mock_dnssec.return_value.validate.assert_called_once_with(sample_domain)
        mock_caa.return_value.analyze.assert_called_once_with(sample_domain)
        mock_rdap.return_value.report.assert_called_once_with(sample_domain)
        assert result['security']['dnssec'] == {'status': 'secure'}
        assert result['security']['caa'] == {'present': True}
        assert result['security']['rdap'] == {'registrar': 'X'}

    @patch('domain_profiler.profiler.Takeover')
    @patch('domain_profiler.profiler.TLSInspector')
    @patch('domain_profiler.profiler.RDAP')
    @patch('domain_profiler.profiler.CAA')
    @patch('domain_profiler.profiler.DNSSEC')
    def test_security_command_normalizes_and_delegates(
        self, mock_dnssec, mock_caa, mock_rdap, mock_tls, mock_takeover
    ):
        """The standalone security() command normalizes input before delegating."""
        mock_dnssec.return_value.validate.return_value = {'status': 'insecure'}
        mock_caa.return_value.analyze.return_value = {}
        mock_rdap.return_value.report.return_value = {}
        mock_tls.return_value.inspect.return_value = {}
        mock_takeover.return_value.report.return_value = {}

        profiler = Profiler()
        result = profiler.security("https://EXAMPLE.com:8443/path")

        mock_dnssec.return_value.validate.assert_called_once_with("example.com")
        mock_caa.return_value.analyze.assert_called_once_with("example.com")
        mock_rdap.return_value.report.assert_called_once_with("example.com")
        mock_tls.return_value.inspect.assert_called_once_with("example.com")
        mock_takeover.return_value.report.assert_called_once_with("example.com")
        assert set(result) == {"dnssec", "caa", "rdap", "tls", "takeover"}

    @patch('domain_profiler.profiler.TLSInspector')
    def test_tls_command_normalizes_and_delegates(self, mock_tls):
        mock_tls.return_value.inspect.return_value = {"issuer": "X"}
        profiler = Profiler()
        result = profiler.tls("https://example.com/path", port=8443)
        mock_tls.return_value.inspect.assert_called_once_with("example.com", port=8443)
        assert result == {"issuer": "X"}

    @patch('domain_profiler.profiler.Takeover')
    def test_takeover_command_normalizes_and_delegates(self, mock_takeover):
        mock_takeover.return_value.report.return_value = {"wildcard": {}}
        profiler = Profiler()
        profiler.takeover("https://example.com")
        mock_takeover.return_value.report.assert_called_once_with("example.com")

    @patch('domain_profiler.profiler.Typosquat')
    def test_typosquat_command_normalizes_both_args(self, mock_typo):
        mock_typo.return_value.analyze.return_value = {"suspicious": True}
        profiler = Profiler()
        profiler.typosquat("https://paypa1.com", brand="https://paypal.com")
        mock_typo.return_value.analyze.assert_called_once_with("paypa1.com", "paypal.com")

    @patch('domain_profiler.profiler.EmailAuth')
    def test_email_command_normalizes_and_delegates(self, mock_email_auth):
        """Test the standalone email() command normalizes input and delegates."""
        mock_email_instance = Mock()
        mock_email_auth.return_value = mock_email_instance
        mock_email_instance.get_report.return_value = {'domain': 'example.com'}

        profiler = Profiler()
        result = profiler.email("https://example.com:8443/path", dkim_selector="s1")

        mock_email_instance.get_report.assert_called_once_with(
            domain="example.com", dkim_selector="s1"
        )
        assert result['domain'] == 'example.com'

    def test_profiler_inherits_from_base(self):
        """Test that Profiler inherits from Base class."""
        from domain_profiler.base import Base
        profiler = Profiler()
        assert isinstance(profiler, Base)

    @pytest.mark.parametrize("domain,expected_host", [
        ("https://example.com", "example.com"),
        ("http://sub.example.com", "sub.example.com"),
        ("https://example.com:8080", "example.com"),  # port stripped
        ("https://user@example.com", "example.com"),  # userinfo stripped
        ("https://EXAMPLE.COM", "example.com"),  # lowercased
        ("example.com", "example.com"),  # No scheme, used as-is
        ("example.com:8443", "example.com"),  # bare host + port
        ("[2001:db8::1]:443", "2001:db8::1"),  # bare IPv6 literal + port
        ("https://[2001:db8::1]:443", "2001:db8::1"),  # IPv6 literal in a URL
        ("", ""),  # Empty domain
    ])
    @patch('domain_profiler.profiler.DNSCheck')
    def test_domain_parsing_variations(self, mock_dns_check, domain, expected_host):
        """Test various domain input formats normalize to a bare hostname."""
        mock_dns_instance = Mock()
        mock_dns_check.return_value = mock_dns_instance
        mock_dns_instance.get_report.return_value = {'domain': expected_host}

        profiler = Profiler()
        profiler.run(domain, live=False)

        mock_dns_instance.get_report.assert_called_once_with(domain=expected_host) 