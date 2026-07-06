"""Tests for the DNS functionality."""

import pytest
from unittest.mock import Mock, patch, MagicMock
import socket
from dns import resolver, reversename

from domain_profiler.dns import DNSCheck


class TestDNSCheck:
    """Test cases for the DNSCheck class."""

    def test_dns_check_initialization(self):
        """Test that DNSCheck can be initialized."""
        dns_check = DNSCheck()
        assert isinstance(dns_check, DNSCheck)
        assert hasattr(dns_check, 'DNS_RECORDS')
        assert len(dns_check.DNS_RECORDS) > 0

    def test_dns_records_list_contains_common_types(self):
        """Test that DNS_RECORDS contains common record types."""
        dns_check = DNSCheck()
        common_records = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        for record_type in common_records:
            assert record_type in dns_check.DNS_RECORDS

    @patch('domain_profiler.dns.resolver.query')
    def test_get_dns_info_success(self, mock_query, sample_domain):
        """Test successful DNS info retrieval."""
        # Mock DNS responses
        mock_a_response = Mock()
        mock_a_response.to_text.return_value = "93.184.216.34"
        mock_query.return_value = [mock_a_response]

        dns_check = DNSCheck()
        
        # Patch to only test A record for simplicity
        with patch.object(dns_check, 'DNS_RECORDS', ['A']):
            result = dns_check.get_dns_info(sample_domain)

        assert 'A' in result
        assert result['A'] == ["93.184.216.34"]
        mock_query.assert_called_with(sample_domain, 'A', lifetime=DNSCheck.QUERY_TIMEOUT)

    @patch('domain_profiler.dns.resolver.query')
    def test_get_dns_info_handles_exceptions(self, mock_query, sample_domain):
        """Test that DNS info handles exceptions gracefully."""
        mock_query.side_effect = Exception("DNS query failed")

        dns_check = DNSCheck()
        
        with patch.object(dns_check, 'DNS_RECORDS', ['A']):
            result = dns_check.get_dns_info(sample_domain)

        # Should return empty dict when all queries fail
        assert result == {}

    @patch('domain_profiler.dns.resolver.query')
    def test_get_dns_info_multiple_answers(self, mock_query, sample_domain):
        """Test DNS info with multiple answers."""
        mock_response1 = Mock()
        mock_response1.to_text.return_value = "93.184.216.34"
        mock_response2 = Mock()
        mock_response2.to_text.return_value = "93.184.216.35"
        
        mock_query.return_value = [mock_response1, mock_response2]

        dns_check = DNSCheck()
        
        with patch.object(dns_check, 'DNS_RECORDS', ['A']):
            result = dns_check.get_dns_info(sample_domain)

        assert 'A' in result
        assert len(result['A']) == 2
        assert "93.184.216.34" in result['A']
        assert "93.184.216.35" in result['A']

    @patch('domain_profiler.dns.reversename.from_address')
    @patch.object(DNSCheck, 'get_dns_info')
    def test_get_reversename_success(self, mock_get_dns_info, mock_from_address, sample_ip):
        """Test successful reverse name lookup."""
        mock_addr = Mock()
        mock_from_address.return_value = mock_addr
        mock_get_dns_info.return_value = {'PTR': ['example.com']}

        dns_check = DNSCheck()
        result = dns_check.get_reversename(sample_ip)

        mock_from_address.assert_called_once_with(sample_ip)
        # The addr is converted to string in the implementation
        mock_get_dns_info.assert_called_once_with(str(mock_addr))
        assert result == {'PTR': ['example.com']}

    @patch('domain_profiler.dns.reversename.from_address')
    def test_get_reversename_handles_exceptions(self, mock_from_address, sample_ip):
        """Test that reverse name lookup handles exceptions."""
        mock_from_address.side_effect = Exception("Reverse lookup failed")

        dns_check = DNSCheck()
        result = dns_check.get_reversename(sample_ip)

        assert result == {}

    @patch('socket.gethostbyname')
    def test_get_ip_success(self, mock_gethostbyname, sample_domain):
        """Test successful IP address retrieval."""
        mock_gethostbyname.return_value = "93.184.216.34"

        dns_check = DNSCheck()
        result = dns_check.get_ip(sample_domain)

        assert result == "93.184.216.34"
        mock_gethostbyname.assert_called_once_with(sample_domain)

    @patch('socket.gethostbyname')
    def test_get_ip_handles_exceptions(self, mock_gethostbyname, sample_domain):
        """Test that get_ip handles exceptions."""
        mock_gethostbyname.side_effect = socket.gaierror("Name resolution failed")

        dns_check = DNSCheck()
        result = dns_check.get_ip(sample_domain)

        assert result == ""

    @patch('socket.gethostbyname_ex')
    def test_get_ip_x_success(self, mock_gethostbyname_ex, sample_domain):
        """Test successful extended IP address retrieval."""
        mock_gethostbyname_ex.return_value = (
            sample_domain, 
            [], 
            ["93.184.216.34", "93.184.216.35"]
        )

        dns_check = DNSCheck()
        result = dns_check.get_ip_x(sample_domain)

        assert result == ["93.184.216.34", "93.184.216.35"]
        mock_gethostbyname_ex.assert_called_once_with(sample_domain)

    @patch('socket.gethostbyname_ex')
    def test_get_ip_x_handles_exceptions(self, mock_gethostbyname_ex, sample_domain):
        """Test that get_ip_x handles exceptions."""
        mock_gethostbyname_ex.side_effect = socket.gaierror("Name resolution failed")

        dns_check = DNSCheck()
        result = dns_check.get_ip_x(sample_domain)

        assert result == []

    @patch('socket.gethostbyaddr')
    def test_get_host_success(self, mock_gethostbyaddr, sample_ip):
        """Test successful hostname retrieval."""
        mock_gethostbyaddr.return_value = ("example.com", [], [])

        dns_check = DNSCheck()
        result = dns_check.get_host(sample_ip)

        assert result == "example.com"  # bare hostname, no repr() quotes
        mock_gethostbyaddr.assert_called_once_with(sample_ip)

    @patch('socket.gethostbyaddr')
    def test_get_host_handles_exceptions(self, mock_gethostbyaddr, sample_ip):
        """Test that get_host handles exceptions."""
        mock_gethostbyaddr.side_effect = socket.herror("Host not found")

        dns_check = DNSCheck()
        result = dns_check.get_host(sample_ip)

        assert result == ""

    @patch('socket.gethostbyaddr')
    def test_get_fqdn_success(self, mock_gethostbyaddr, sample_ip):
        """Test successful FQDN retrieval."""
        mock_gethostbyaddr.return_value = ("example.com", [], [])

        dns_check = DNSCheck()
        result = dns_check.get_fqdn(sample_ip)

        assert result == "example.com"
        mock_gethostbyaddr.assert_called_once_with(sample_ip)

    @patch('socket.gethostbyaddr')
    def test_get_fqdn_handles_exceptions(self, mock_gethostbyaddr, sample_ip):
        """Test that get_fqdn handles exceptions."""
        mock_gethostbyaddr.side_effect = socket.herror("Host not found")

        dns_check = DNSCheck()
        result = dns_check.get_fqdn(sample_ip)

        assert result == ""

    @patch('socket.gethostbyname_ex')
    def test_get_aliases_success(self, mock_gethostbyname_ex, sample_domain):
        """Test successful aliases retrieval."""
        mock_gethostbyname_ex.return_value = (
            sample_domain,
            ["www.example.com", "mail.example.com"],
            ["93.184.216.34"]
        )

        dns_check = DNSCheck()
        result = dns_check.get_aliases(sample_domain)

        assert result == ["www.example.com", "mail.example.com"]
        mock_gethostbyname_ex.assert_called_once_with(sample_domain)

    @patch('socket.gethostbyname_ex')
    def test_get_aliases_handles_exceptions(self, mock_gethostbyname_ex, sample_domain):
        """Test that get_aliases handles exceptions."""
        mock_gethostbyname_ex.side_effect = socket.gaierror("Name resolution failed")

        dns_check = DNSCheck()
        result = dns_check.get_aliases(sample_domain)

        assert result == []

    @patch.object(DNSCheck, 'get_dns_info')
    @patch.object(DNSCheck, 'get_reversename')
    @patch.object(DNSCheck, 'get_fqdn')
    @patch.object(DNSCheck, 'get_host')
    @patch.object(DNSCheck, 'get_aliases')
    @patch.object(DNSCheck, 'get_ip_x')
    @patch.object(DNSCheck, 'get_ip')
    def test_get_report_comprehensive(self, mock_get_ip, mock_get_ip_x, mock_get_aliases,
                                    mock_get_host, mock_get_fqdn, mock_get_reversename,
                                    mock_get_dns_info, sample_domain):
        """Test comprehensive report generation."""
        # Setup mocks
        mock_get_ip.return_value = "93.184.216.34"
        mock_get_ip_x.return_value = ["93.184.216.34", "93.184.216.35"]
        mock_get_aliases.return_value = ["www.example.com"]
        mock_get_host.return_value = "example.com"
        mock_get_fqdn.return_value = "example.com"
        mock_get_reversename.return_value = {"PTR": ["example.com"]}
        mock_get_dns_info.return_value = {"A": ["93.184.216.34"]}

        dns_check = DNSCheck()
        result = dns_check.get_report(sample_domain)

        # Verify structure
        assert result['domain'] == sample_domain
        assert result['aliases'] == ["www.example.com"]
        assert result['dns'] == {"A": ["93.184.216.34"]}
        assert 'ips' in result
        
        # Verify IP data structure
        ips = result['ips']
        assert "93.184.216.34" in ips
        assert "93.184.216.35" in ips
        
        # Verify IP details
        ip_data = ips["93.184.216.34"]
        assert ip_data["host"] == "example.com"
        assert ip_data["fqdn"] == "example.com"
        assert ip_data["reverse"] == {"PTR": ["example.com"]}

    @patch.object(DNSCheck, 'get_ip')
    @patch.object(DNSCheck, 'get_ip_x')
    def test_get_report_deduplicates_ips(self, mock_get_ip_x, mock_get_ip, sample_domain):
        """Test that get_report deduplicates IP addresses."""
        mock_get_ip.return_value = "93.184.216.34"
        mock_get_ip_x.return_value = ["93.184.216.34", "93.184.216.34"]  # Duplicate IPs
        
        with patch.object(DNSCheck, 'get_aliases', return_value=[]):
            with patch.object(DNSCheck, 'get_dns_info', return_value={}):
                with patch.object(DNSCheck, 'get_host', return_value=""):
                    with patch.object(DNSCheck, 'get_fqdn', return_value=""):
                        with patch.object(DNSCheck, 'get_reversename', return_value={}):
                            dns_check = DNSCheck()
                            result = dns_check.get_report(sample_domain)

        # Should only have one entry for the IP
        assert len(result['ips']) == 1
        assert "93.184.216.34" in result['ips']

    def test_dns_check_inherits_from_base(self):
        """Test that DNSCheck inherits from Base class."""
        from domain_profiler.base import Base
        dns_check = DNSCheck()
        assert isinstance(dns_check, Base)

    @pytest.mark.parametrize("record_type", [
        'A', 'AAAA', 'MX', 'NS', 'CNAME', 'SOA', 'PTR'
    ])
    @patch('domain_profiler.dns.resolver.query')
    def test_get_dns_info_individual_record_types(self, mock_query, record_type, sample_domain):
        """Test DNS info retrieval for individual record types."""
        mock_response = Mock()
        mock_response.to_text.return_value = f"mock-{record_type}-value"
        mock_query.return_value = [mock_response]

        dns_check = DNSCheck()
        
        with patch.object(dns_check, 'DNS_RECORDS', [record_type]):
            result = dns_check.get_dns_info(sample_domain)

        assert record_type in result
        assert result[record_type] == [f"mock-{record_type}-value"]

    def test_parse_txt_record_extracts_all_spf_ips(self):
        """SPF ip4/ip6 mechanisms are all extracted, not just the first."""
        dns_check = DNSCheck()
        record = 'v=spf1 ip4:1.2.3.4 ip4:5.6.7.8 ip6:2001:db8::1 -all'

        result = dns_check._parse_txt_record(record)

        assert result == ['1.2.3.4', '5.6.7.8', '2001:db8::1']

    def test_parse_txt_record_ignores_non_ips(self):
        """Non-SPF TXT records yield no IPs rather than raising."""
        dns_check = DNSCheck()
        assert dns_check._parse_txt_record('google-site-verification=abc') == []

    def test_dns_records_excludes_obsolete_and_meta_types(self):
        """The record set is trimmed to useful types (no AXFR/ANY/obsolete)."""
        dns_check = DNSCheck()
        for absent in ('AXFR', 'IXFR', 'ANY', 'MD', 'MF', 'NULL', 'OPT'):
            assert absent not in dns_check.DNS_RECORDS

    @patch('domain_profiler.dns.resolver.query')
    def test_get_dns_info_passes_query_timeout(self, mock_query, sample_domain):
        """Each resolver query is bounded by a lifetime timeout."""
        mock_response = Mock()
        mock_response.to_text.return_value = "93.184.216.34"
        mock_query.return_value = [mock_response]

        dns_check = DNSCheck()
        with patch.object(dns_check, 'DNS_RECORDS', ['A']):
            dns_check.get_dns_info(sample_domain)

        mock_query.assert_called_with(
            sample_domain, 'A', lifetime=DNSCheck.QUERY_TIMEOUT
        )

    @patch.object(DNSCheck, 'get_ip')
    @patch.object(DNSCheck, 'get_ip_x')
    def test_get_report_drops_empty_ip(self, mock_get_ip_x, mock_get_ip, sample_domain):
        """A failed resolution ("") must not become a bogus IP entry."""
        mock_get_ip.return_value = ""  # resolution failed
        mock_get_ip_x.return_value = []

        with patch.object(DNSCheck, 'get_aliases', return_value=[]):
            with patch.object(DNSCheck, 'get_dns_info', return_value={}):
                dns_check = DNSCheck()
                result = dns_check.get_report(sample_domain)

        assert result['ips'] == {}

    @patch('domain_profiler.dns.resolver.query')
    def test_get_dns_info_with_list_response(self, mock_query, sample_domain):
        """Test DNS info with list-type response from to_text()."""
        mock_response = Mock()
        mock_response.to_text.return_value = ["value1", "value2"]  # List response
        mock_query.return_value = [mock_response]

        dns_check = DNSCheck()

        with patch.object(dns_check, 'DNS_RECORDS', ['MX']):
            result = dns_check.get_dns_info(sample_domain)

        assert 'MX' in result
        assert "value1" in result['MX']
        assert "value2" in result['MX']


class TestIsIpInCidr:
    """Cover is_ip_in_cidr — previously had no test at all (4 no-cov mutants)."""

    def test_ipv4_in_range(self):
        assert DNSCheck().is_ip_in_cidr("10.0.0.5", "10.0.0.0/24") is True

    def test_ipv4_out_of_range(self):
        assert DNSCheck().is_ip_in_cidr("10.0.1.5", "10.0.0.0/24") is False

    def test_ipv6_in_range(self):
        assert DNSCheck().is_ip_in_cidr("2001:db8::1", "2001:db8::/32") is True

    def test_invalid_ip_returns_false(self):
        assert DNSCheck().is_ip_in_cidr("not-an-ip", "10.0.0.0/24") is False

    def test_invalid_cidr_returns_false(self):
        assert DNSCheck().is_ip_in_cidr("10.0.0.5", "garbage") is False

    def test_boundary_addresses(self):
        # Network and broadcast addresses are both within the range.
        assert DNSCheck().is_ip_in_cidr("10.0.0.0", "10.0.0.0/24") is True
        assert DNSCheck().is_ip_in_cidr("10.0.0.255", "10.0.0.0/24") is True


class TestGetDnsInfoTxtParsing:
    """Exercise the real TXT branch of get_dns_info (kills TXT-key + parse mutants)."""

    @patch('domain_profiler.dns.resolver.query')
    def test_txt_record_ips_extracted_into_result(self, mock_query, sample_domain):
        resp = Mock()
        resp.to_text.return_value = '"v=spf1 ip4:1.2.3.4 ip4:5.6.7.8 -all"'
        mock_query.return_value = [resp]
        dns_check = DNSCheck()
        with patch.object(dns_check, 'DNS_RECORDS', ['TXT']):
            result = dns_check.get_dns_info(sample_domain)
        # The "TXT" key must be used verbatim and both ip4 values extracted.
        assert result["TXT"] == ["1.2.3.4", "5.6.7.8"]

    @patch('domain_profiler.dns.resolver.query')
    def test_txt_continues_past_first_record(self, mock_query, sample_domain):
        """Multiple TXT rdata: a later record's IPs are still collected.

        Kills the `continue`->`break` mutant — `break` would stop after the
        first (IP-less) TXT record and drop the second record's IPs.
        """
        r1 = Mock(); r1.to_text.return_value = '"v=verification=abc"'  # no IPs
        r2 = Mock(); r2.to_text.return_value = '"v=spf1 ip4:9.9.9.9 -all"'
        mock_query.return_value = [r1, r2]
        dns_check = DNSCheck()
        with patch.object(dns_check, 'DNS_RECORDS', ['TXT']):
            result = dns_check.get_dns_info(sample_domain)
        assert result["TXT"] == ["9.9.9.9"]


class TestParseTxtRecordReal:
    """Assert _parse_txt_record's quote/whitespace handling (kills replace mutants)."""

    def test_quotes_stripped_and_split_on_whitespace(self):
        dns_check = DNSCheck()
        # Leading/trailing quotes must be turned into spaces so ip4:1.2.3.4 parses.
        assert dns_check._parse_txt_record('"ip4:1.2.3.4"') == ["1.2.3.4"]

    def test_quote_between_tokens_does_not_merge_ips(self):
        dns_check = DNSCheck()
        # If '"' were replaced with '' instead of ' ', these would merge/fail.
        assert dns_check._parse_txt_record('ip4:1.2.3.4"ip4:5.6.7.8') == ["1.2.3.4", "5.6.7.8"]


class TestGetReportArgWiring:
    """Assert get_report passes the real domain/ip through (kills =None mutants)."""

    def test_report_passes_domain_and_ips_through(self, sample_domain):
        dns_check = DNSCheck()
        with patch.object(DNSCheck, 'get_ip', return_value="1.2.3.4") as m_ip, \
             patch.object(DNSCheck, 'get_ip_x', return_value=[]) as m_ipx, \
             patch.object(DNSCheck, 'get_aliases', return_value=[]) as m_al, \
             patch.object(DNSCheck, 'get_dns_info', return_value={}) as m_dns, \
             patch.object(DNSCheck, 'get_host', return_value="h") as m_host, \
             patch.object(DNSCheck, 'get_fqdn', return_value="f") as m_fqdn, \
             patch.object(DNSCheck, 'get_reversename', return_value={}) as m_rev:
            result = dns_check.get_report(sample_domain)

        # domain flows to the domain-keyed lookups...
        m_ip.assert_called_once_with(domain=sample_domain)
        m_ipx.assert_called_once_with(domain=sample_domain)
        m_al.assert_called_once_with(domain=sample_domain)
        m_dns.assert_called_once_with(domain=sample_domain)
        # ...and the resolved IP (not None) flows to the ip-keyed lookups.
        m_host.assert_called_once_with(ip_address="1.2.3.4")
        m_fqdn.assert_called_once_with(ip_address="1.2.3.4")
        m_rev.assert_called_once_with(ip_address="1.2.3.4")
        assert result["ips"]["1.2.3.4"]["host"] == "h"