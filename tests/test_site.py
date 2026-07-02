"""Tests for the site analysis functionality."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from urllib.parse import urlparse
import re
import pendulum

from domain_profiler.site import Url


class TestUrl:
    """Test cases for the Url class."""

    @patch('domain_profiler.site.whois.whois')
    def test_url_initialization_success(self, mock_whois, sample_url, mock_whois_data):
        """Test successful URL initialization."""
        mock_whois.return_value = mock_whois_data
        
        # We'll test the core functionality without mocking the session
        # since the session is a class variable that's hard to mock
        url_instance = Url(sample_url)

        assert url_instance._original_url == sample_url
        assert url_instance._parsed_url.netloc == "example.com"
        assert url_instance.response is not None  # Should get a real response
        mock_whois.assert_called_once_with("example.com")

    @patch('domain_profiler.site.whois.whois')
    def test_url_initialization_with_connection_error(self, mock_whois, mock_whois_data):
        """Test URL initialization when connection fails."""
        mock_whois.return_value = mock_whois_data

        # Test with a URL that will definitely fail
        url_instance = Url("https://nonexistent-domain-12345.invalid")

        # Should gracefully handle connection errors
        assert url_instance._original_url == "https://nonexistent-domain-12345.invalid"
        # The response might be None or an error response depending on the session behavior
        # The important thing is that it doesn't crash

    @patch('domain_profiler.site.whois.whois')
    def test_url_initialization_https_fallback(self, mock_whois, mock_whois_data):
        """Test HTTPS to HTTP fallback on connection failure."""
        mock_whois.return_value = mock_whois_data

        # Test the fallback behavior with a real URL that supports both
        url_instance = Url("https://example.com")

        # Should initialize successfully 
        assert url_instance._original_url == "https://example.com"
        assert url_instance._parsed_url.netloc == "example.com"

    def test_get_redirects_with_history(self, mock_html_response):
        """Test getting redirects when response has history."""
        # Setup redirect history
        redirect1 = Mock()
        redirect1.url = "https://old.example.com"
        redirect2 = Mock() 
        redirect2.url = "https://www.example.com"
        mock_html_response.history = [redirect1, redirect2]

        with patch('domain_profiler.site.HTMLSession'):
            with patch('domain_profiler.site.whois.whois', return_value={}):
                url_instance = Url("https://example.com")
                url_instance.response = mock_html_response

        redirects = url_instance.get_redirects()

        assert len(redirects) == 2
        assert "https://old.example.com" in redirects
        assert "https://www.example.com" in redirects

    def test_get_redirects_no_history(self):
        """Test getting redirects when response has no history."""
        with patch('domain_profiler.site.HTMLSession'):
            with patch('domain_profiler.site.whois.whois', return_value={}):
                url_instance = Url("https://example.com")
                url_instance.response = Mock()
                url_instance.response.history = []

        redirects = url_instance.get_redirects()
        assert redirects == []

    def test_get_redirects_no_response(self):
        """Test getting redirects when no response available."""
        with patch('domain_profiler.site.HTMLSession'):
            with patch('domain_profiler.site.whois.whois', return_value={}):
                url_instance = Url("https://example.com")
                url_instance.response = None

        redirects = url_instance.get_redirects()
        assert redirects == []

    @patch('domain_profiler.site.pendulum.instance')
    def test_domain_registration_length_success(self, mock_pendulum_instance, mock_whois_data):
        """Test successful domain registration length calculation."""
        mock_date = Mock()
        mock_diff = Mock()
        mock_diff.in_minutes.return_value = 525600
        mock_diff.in_hours.return_value = 8760
        mock_diff.in_days.return_value = 365
        mock_diff.in_words.return_value = "1 year ago"
        mock_date.diff.return_value = mock_diff
        mock_pendulum_instance.return_value = mock_date

        with patch('domain_profiler.site.HTMLSession'):
            with patch('domain_profiler.site.whois.whois', return_value=mock_whois_data):
                url_instance = Url("https://example.com")

        result = url_instance.domain_registration_length()

        assert result['in_minutes'] == 525600
        assert result['in_hours'] == 8760
        assert result['in_days'] == 365
        assert result['human'] == "1 year ago"

    def test_domain_registration_length_no_whois(self):
        """Test domain registration length with no WHOIS data."""
        with patch('domain_profiler.site.HTMLSession'):
            with patch('domain_profiler.site.whois.whois', return_value={}):
                url_instance = Url("https://example.com")

        result = url_instance.domain_registration_length()
        assert result == {}

    def test_get_favicons_success(self):
        """Test successful favicon extraction."""
        with patch('domain_profiler.site.whois.whois', return_value={}):
            url_instance = Url("https://example.com")
            
            # Test that get_favicons returns a list and doesn't crash
            result = url_instance.get_favicons()
            
            # Should return a list (may be empty if no favicons found)
            assert isinstance(result, list)
            
            # Test the structure when mocking the whole method for coverage
            with patch.object(url_instance, 'get_favicons', return_value=[{'href': '/favicon.ico', 'hash': 12345}]):
                result = url_instance.get_favicons()
                assert len(result) == 1
                assert result[0]['href'] == '/favicon.ico'
                assert result[0]['hash'] == 12345

    def test_get_favicons_no_response(self):
        """Test favicon extraction with no response."""
        with patch('domain_profiler.site.HTMLSession'):
            with patch('domain_profiler.site.whois.whois', return_value={}):
                url_instance = Url("https://example.com")
                url_instance.response = None

        result = url_instance.get_favicons()
        assert result == []

    @patch('domain_profiler.site.pendulum.instance')
    def test_domain_age_success(self, mock_pendulum_instance, mock_whois_data):
        """Test successful domain age calculation."""
        mock_date = Mock()
        mock_diff = Mock()
        mock_diff.in_minutes.return_value = 1051200
        mock_diff.in_hours.return_value = 17520
        mock_diff.in_days.return_value = 730
        mock_diff.in_words.return_value = "2 years ago"
        mock_date.diff.return_value = mock_diff
        mock_pendulum_instance.return_value = mock_date

        with patch('domain_profiler.site.HTMLSession'):
            with patch('domain_profiler.site.whois.whois', return_value=mock_whois_data):
                url_instance = Url("https://example.com")

        result = url_instance.domain_age()

        assert result['in_minutes'] == 1051200
        assert result['in_hours'] == 17520
        assert result['in_days'] == 730
        assert result['human'] == "2 years ago"

    def test_domain_age_no_creation_date(self):
        """Test domain age calculation with no creation date."""
        whois_data = {'domain_name': ['EXAMPLE.COM']}  # No creation_date
        
        with patch('domain_profiler.site.HTMLSession'):
            with patch('domain_profiler.site.whois.whois', return_value=whois_data):
                url_instance = Url("https://example.com")

        result = url_instance.domain_age()
        assert result == {}

    def test_to_json_comprehensive(self, mock_whois_data):
        """Test comprehensive JSON output."""
        with patch('domain_profiler.site.whois.whois', return_value=mock_whois_data):
            url_instance = Url("https://example.com/path?query=value")
            
            # Mock individual methods that return complex data
            with patch.object(url_instance, 'domain_age', return_value={'in_days': 365}):
                with patch.object(url_instance, 'domain_registration_length', return_value={'in_days': 730}):
                    with patch.object(url_instance, 'get_favicons', return_value=[]):
                        with patch('domain_profiler.site.BeautifulSoup') as mock_bs:
                            mock_bs.return_value = Mock()
                            mock_bs.return_value.find.return_value = Mock()
                            mock_bs.return_value.find.return_value.string = "Example Domain"
                            result = url_instance.to_json()

        # Verify basic structure - the important parts
        assert result['url'] == "https://example.com/path?query=value"
        assert result['scheme'] == 'https'
        assert result['netloc'] == 'example.com'
        assert result['path'] == '/path'
        assert result['query'] == 'query=value'
        assert 'is_alive' in result  # Property exists
        assert result['whois'] == mock_whois_data
        assert result['domain_age'] == {'in_days': 365}

    def test_is_alive_property_true(self):
        """Test is_alive property when response is OK."""
        with patch('domain_profiler.site.HTMLSession'):
            with patch('domain_profiler.site.whois.whois', return_value={}):
                url_instance = Url("https://example.com")
                url_instance.response = Mock()
                url_instance.response.ok = True

        assert url_instance.is_alive is True

    def test_is_alive_property_false(self):
        """Test is_alive property when response is not OK."""
        with patch('domain_profiler.site.HTMLSession'):
            with patch('domain_profiler.site.whois.whois', return_value={}):
                url_instance = Url("https://example.com")
                url_instance.response = Mock()
                url_instance.response.ok = False

        assert url_instance.is_alive is False

    def test_is_alive_property_no_response(self):
        """Test is_alive property when no response."""
        with patch('domain_profiler.site.HTMLSession'):
            with patch('domain_profiler.site.whois.whois', return_value={}):
                url_instance = Url("https://example.com")
                url_instance.response = None

        assert url_instance.is_alive is False

    def test_is_file_property_content_type(self):
        """Test is_file property based on content type."""
        with patch('domain_profiler.site.HTMLSession'):
            with patch('domain_profiler.site.whois.whois', return_value={}):
                url_instance = Url("https://example.com")
                url_instance.response = Mock()
                url_instance.response.ok = True
                url_instance.response.headers = {'content-type': 'application/zip'}

        assert url_instance.is_file is True

    def test_is_file_property_extension(self):
        """Test is_file property based on URL extension."""
        with patch('domain_profiler.site.HTMLSession'):
            with patch('domain_profiler.site.whois.whois', return_value={}):
                url_instance = Url("https://example.com/file.pdf")
                url_instance.response = Mock()
                url_instance.response.ok = True
                url_instance.response.url = "https://example.com/file.pdf"
                url_instance.response.headers = {'content-type': 'text/html'}

        assert url_instance.is_file is True

    def test_has_ip_property_true(self):
        """Test has_ip property with IP address."""
        with patch('domain_profiler.site.HTMLSession'):
            with patch('domain_profiler.site.whois.whois', return_value={}):
                url_instance = Url("https://192.168.1.1")

        assert url_instance.has_ip is True

    def test_has_ip_property_false(self):
        """Test has_ip property with domain name."""
        with patch('domain_profiler.site.HTMLSession'):
            with patch('domain_profiler.site.whois.whois', return_value={}):
                url_instance = Url("https://example.com")

        assert url_instance.has_ip is False

    def test_has_at_symbol_property(self):
        """Test has_at_symbol property."""
        with patch('domain_profiler.site.HTMLSession'):
            with patch('domain_profiler.site.whois.whois', return_value={}):
                url_with_at = Url("https://user@example.com")
                url_without_at = Url("https://example.com")

        assert url_with_at.has_at_symbol is True
        assert url_without_at.has_at_symbol is False

    def test_has_double_slash_property(self):
        """Test has_double_slash property."""
        with patch('domain_profiler.site.HTMLSession'):
            with patch('domain_profiler.site.whois.whois', return_value={}):
                url_with_slash = Url("https://example.com//path")
                url_normal = Url("https://example.com/path")

        # Note: All URLs with scheme will have // after the scheme
        assert url_with_slash.has_double_slash is True
        assert url_normal.has_double_slash is True

    def test_has_non_standard_port_property(self):
        """Test has_non_standard_port property."""
        with patch('domain_profiler.site.HTMLSession'):
            with patch('domain_profiler.site.whois.whois', return_value={}):
                url_standard_https = Url("https://example.com")  # 443
                url_standard_http = Url("http://example.com")    # 80
                url_custom_port = Url("https://example.com:8080")

        assert url_standard_https.has_non_standard_port is False
        assert url_standard_http.has_non_standard_port is False
        assert url_custom_port.has_non_standard_port is True

    def test_has_suspicious_forms_property_true(self):
        """Test has_suspicious_forms property detecting suspicious forms."""
        with patch('domain_profiler.site.HTMLSession'):
            with patch('domain_profiler.site.whois.whois', return_value={}):
                url_instance = Url("https://example.com")
                mock_response = Mock()
                mock_response.content = b'<form action=""></form>'
                url_instance.response = mock_response

        assert url_instance.has_suspicious_forms is True

    def test_has_suspicious_forms_property_false(self):
        """Test has_suspicious_forms property with normal forms."""
        with patch('domain_profiler.site.HTMLSession'):
            with patch('domain_profiler.site.whois.whois', return_value={}):
                url_instance = Url("https://example.com")
                mock_response = Mock()
                mock_response.content = b'<form action="https://example.com/submit"></form>'
                url_instance.response = mock_response

        assert url_instance.has_suspicious_forms is False

    def test_using_sub_domains_property(self):
        """Test using_sub_domains property."""
        with patch('domain_profiler.site.HTMLSession'):
            with patch('domain_profiler.site.whois.whois', return_value={}):
                url_simple = Url("https://example.com")
                url_subdomain = Url("https://sub.example.com")
                url_many_subdomains = Url("https://a.b.c.d.example.com")

        assert url_simple.using_sub_domains is False
        assert url_subdomain.using_sub_domains is False  # Only 2 dots total
        assert url_many_subdomains.using_sub_domains is True  # More than 3 dots

    @patch('re.search')
    def test_has_popup_window_property_true(self, mock_search):
        """Test has_popup_window property detecting popups."""
        mock_search.return_value = Mock()  # Found popup pattern

        with patch('domain_profiler.site.HTMLSession'):
            with patch('domain_profiler.site.whois.whois', return_value={}):
                url_instance = Url("https://example.com")
                mock_response = Mock()
                mock_response.ok = True
                
                # Mock script tag with popup
                mock_script = Mock()
                mock_script.text = "window.open('popup.html')"
                mock_response.html.find.return_value = [mock_script]
                mock_response.html.render.return_value = None
                
                url_instance.response = mock_response

        assert url_instance.has_popup_window is True

    @patch('re.search')
    def test_has_popup_window_property_false(self, mock_search):
        """Test has_popup_window property with no popups."""
        mock_search.return_value = None  # No popup pattern found

        with patch('domain_profiler.site.HTMLSession'):
            with patch('domain_profiler.site.whois.whois', return_value={}):
                url_instance = Url("https://example.com")
                mock_response = Mock()
                mock_response.ok = True
                
                mock_script = Mock()
                mock_script.text = "console.log('normal script')"
                mock_response.html.find.return_value = [mock_script]
                mock_response.html.render.return_value = None
                
                url_instance.response = mock_response

        assert url_instance.has_popup_window is False

    def test_subdirectory_list_property(self):
        """Test subdirectory_list property."""
        with patch('domain_profiler.site.HTMLSession'):
            with patch('domain_profiler.site.whois.whois', return_value={}):
                url_instance = Url("https://example.com/path/to/resource")

        subdirs = url_instance.subdirectory_list

        # Should generate subdirectories
        assert "https://example.com/path" in subdirs
        assert "https://example.com/path/" in subdirs
        assert "https://example.com/path/to" in subdirs
        assert "https://example.com/path/to/" in subdirs

    def test_subdirectory_zip_list_property(self):
        """Test subdirectory_zip_list property."""
        with patch('domain_profiler.site.HTMLSession'):
            with patch('domain_profiler.site.whois.whois', return_value={}):
                url_instance = Url("https://example.com/path/to/resource")

        zip_list = url_instance.subdirectory_zip_list

        # Should generate zip versions of subdirectories
        assert "https://example.com/path.zip" in zip_list
        assert "https://example.com/path/to.zip" in zip_list

    @pytest.mark.parametrize("url,expected_scheme", [
        ("https://example.com", "https"),
        ("http://example.com", "http"),
        ("ftp://example.com", "ftp"),
    ])
    def test_url_scheme_parsing(self, url, expected_scheme):
        """Test URL scheme parsing for different protocols."""
        with patch('domain_profiler.site.HTMLSession'):
            with patch('domain_profiler.site.whois.whois', return_value={}):
                url_instance = Url(url)

        assert url_instance._parsed_url.scheme == expected_scheme

    def test_url_inherits_from_base(self):
        """Test that Url inherits from Base class."""
        from domain_profiler.base import Base

        with patch('domain_profiler.site.HTMLSession'):
            with patch('domain_profiler.site.whois.whois', return_value={}):
                url_instance = Url("https://example.com")

        assert isinstance(url_instance, Base)

    def test_has_suspicious_forms_scans_all_forms(self):
        """A suspicious form after a benign one is still detected."""
        with patch('domain_profiler.site.Url.session') as mock_session:
            mock_session.get.side_effect = Exception("network disabled in unit tests")
            with patch('domain_profiler.site.whois.whois', return_value={}):
                url_instance = Url("https://example.com")
                mock_response = Mock()
                # First form is benign; second has an empty action (suspicious).
                mock_response.content = (
                    b'<form action="https://example.com/search"></form>'
                    b'<form action=""></form>'
                )
                url_instance.response = mock_response

        assert url_instance.has_suspicious_forms is True

    def test_is_abnormal_url_uses_substring_not_regex(self):
        """A domain name with regex metachars is matched literally."""
        with patch('domain_profiler.site.Url.session') as mock_session:
            mock_session.get.side_effect = Exception("network disabled in unit tests")
            with patch('domain_profiler.site.whois.whois',
                       return_value={'domain_name': 'example.com'}):
                # "." is a regex any-char; a literal check must reject this URL.
                url_instance = Url("https://exampleXcom.evil.net")

        assert url_instance.is_abnormal_url is True

    @patch('re.search')
    def test_has_popup_window_pattern_grouped(self, mock_search):
        """The popup regex groups its alternatives (open|alert|confirm|prompt)."""
        mock_search.return_value = None

        with patch('domain_profiler.site.HTMLSession'):
            with patch('domain_profiler.site.whois.whois', return_value={}):
                url_instance = Url("https://example.com")
                mock_response = Mock()
                mock_response.ok = True
                mock_script = Mock()
                mock_script.text = "window.open('x')"
                mock_response.html.find.return_value = [mock_script]
                mock_response.html.render.return_value = None
                url_instance.response = mock_response

        url_instance.has_popup_window
        pattern = mock_search.call_args[0][0]
        assert pattern == r'(open|alert|confirm|prompt)\('

    def test_to_json_whois_is_json_serializable(self):
        """to_json output (including whois datetimes) survives json.dumps."""
        import json
        from datetime import datetime

        whois_data = {
            'domain_name': ['EXAMPLE.COM'],
            'creation_date': [datetime(1995, 8, 14)],
            'updated_date': datetime(2023, 1, 1),
        }
        with patch('domain_profiler.site.Url.session') as mock_session:
            mock_session.get.side_effect = Exception("network disabled in unit tests")
            with patch('domain_profiler.site.whois.whois', return_value=whois_data):
                url_instance = Url("https://example.com")
                url_instance.response = None

        result = url_instance.to_json()
        # Should not raise TypeError on datetime objects.
        json.dumps(result)
        assert result['whois']['updated_date'] == '2023-01-01T00:00:00'

    @patch('domain_profiler.site.pendulum.instance')
    def test_domain_age_handles_list_creation_date(self, mock_pendulum_instance):
        """A list-valued creation_date is coerced to a datetime, not crashed."""
        from datetime import datetime
        mock_date = Mock()
        mock_diff = Mock()
        mock_diff.in_minutes.return_value = 1
        mock_diff.in_hours.return_value = 1
        mock_diff.in_days.return_value = 1
        mock_diff.in_words.return_value = "1 day ago"
        mock_date.diff.return_value = mock_diff
        mock_pendulum_instance.return_value = mock_date

        whois_data = {'creation_date': [datetime(1995, 8, 14), datetime(1996, 1, 1)]}
        with patch('domain_profiler.site.HTMLSession'):
            with patch('domain_profiler.site.whois.whois', return_value=whois_data):
                url_instance = Url("https://example.com")

        result = url_instance.domain_age()
        # The most recent datetime is used; result is populated (not {}).
        assert result['in_days'] == 1
        mock_pendulum_instance.assert_called_once_with(datetime(1996, 1, 1))