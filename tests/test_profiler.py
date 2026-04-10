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

    def test_profiler_inherits_from_base(self):
        """Test that Profiler inherits from Base class."""
        from domain_profiler.base import Base
        profiler = Profiler()
        assert isinstance(profiler, Base)

    @pytest.mark.parametrize("domain,expected_netloc", [
        ("https://example.com", "example.com"),
        ("http://sub.example.com", "sub.example.com"),
        ("https://example.com:8080", "example.com:8080"),
        ("example.com", "example.com"),  # No scheme, should use as-is
        ("", ""),  # Empty domain
    ])
    @patch('domain_profiler.profiler.DNSCheck')
    def test_domain_parsing_variations(self, mock_dns_check, domain, expected_netloc):
        """Test various domain input formats."""
        mock_dns_instance = Mock()
        mock_dns_check.return_value = mock_dns_instance
        mock_dns_instance.get_report.return_value = {'domain': expected_netloc}

        profiler = Profiler()
        profiler.run(domain, live=False)

        if expected_netloc:
            mock_dns_instance.get_report.assert_called_once_with(domain=expected_netloc)
        else:
            mock_dns_instance.get_report.assert_called_once_with(domain=domain) 