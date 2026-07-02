"""Tests for DNSSEC chain validation."""

from unittest.mock import Mock, patch

import dns.flags
import dns.rcode
import dns.rdatatype

from domain_profiler.dnssec import DNSSEC, WEAK_DNSSEC_ALGORITHMS


class TestDNSSEC:
    """Test cases for the DNSSEC class using mocked DNS transport."""

    def _mock_key(self, algorithm=13):
        key = Mock()
        key.algorithm = algorithm
        return key

    def test_unsigned_zone_is_insecure(self):
        """A zone with no DNSKEY and no SERVFAIL is insecure, not an error."""
        d = DNSSEC()
        empty_response = Mock()
        empty_response.answer = []
        with patch.object(d, "_resolver_ad_flag", return_value=False):
            with patch.object(d, "_fetch_with_rrsig", return_value=empty_response):
                with patch.object(d, "_is_bogus_servfail", return_value=False):
                    result = d.validate("example.org")

        assert result["status"] == "insecure"
        assert result["signed"] is False

    def test_no_dnskey_but_servfail_is_bogus(self):
        """No keys returned + validating resolver SERVFAIL = bogus chain."""
        d = DNSSEC()
        empty_response = Mock()
        empty_response.answer = []
        with patch.object(d, "_resolver_ad_flag", return_value=False):
            with patch.object(d, "_fetch_with_rrsig", return_value=empty_response):
                with patch.object(d, "_is_bogus_servfail", return_value=True):
                    result = d.validate("dnssec-failed.example")

        assert result["status"] == "bogus"
        assert any("SERVFAIL" in e for e in result["errors"])

    def test_dnskey_query_failure_is_error(self):
        d = DNSSEC()
        with patch.object(d, "_resolver_ad_flag", return_value=None):
            with patch.object(d, "_fetch_with_rrsig", return_value=None):
                result = d.validate("example.com")
        assert result["status"] == "error"

    def test_secure_chain(self):
        """DNSKEY self-signature valid + parent DS matches = secure."""
        d = DNSSEC()
        dnskey_rrset = [self._mock_key(13)]
        response = Mock()
        with patch.object(d, "_resolver_ad_flag", return_value=True):
            with patch.object(d, "_fetch_with_rrsig", return_value=response):
                with patch.object(
                    d, "_split_rrset_rrsig", return_value=(dnskey_rrset, Mock())
                ):
                    with patch("dns.dnssec.validate", return_value=None):
                        with patch.object(d, "_validate_ds", return_value="match"):
                            result = d.validate("example.com")

        assert result["status"] == "secure"
        assert result["signed"] is True
        assert result["dnskey_validated"] is True
        assert result["ds_validated"] is True
        assert result["algorithms"] == [13]

    def test_bad_dnskey_signature_is_bogus(self):
        """DNSKEY present but self-signature fails validation = bogus."""
        d = DNSSEC()
        dnskey_rrset = [self._mock_key(13)]
        response = Mock()
        with patch.object(d, "_resolver_ad_flag", return_value=False):
            with patch.object(d, "_fetch_with_rrsig", return_value=response):
                with patch.object(
                    d, "_split_rrset_rrsig", return_value=(dnskey_rrset, Mock())
                ):
                    with patch(
                        "dns.dnssec.validate", side_effect=Exception("bad sig")
                    ):
                        result = d.validate("example.com")

        assert result["status"] == "bogus"
        assert any("signature invalid" in e for e in result["errors"])

    def _validate_with_ds_state(self, ds_state, algorithm=13):
        """Run validate() with DNSKEY self-sig OK and _validate_ds → ds_state."""
        d = DNSSEC()
        dnskey_rrset = [self._mock_key(algorithm)]
        response = Mock()
        with patch.object(d, "_resolver_ad_flag", return_value=False):
            with patch.object(d, "_fetch_with_rrsig", return_value=response):
                with patch.object(
                    d, "_split_rrset_rrsig", return_value=(dnskey_rrset, Mock())
                ):
                    with patch("dns.dnssec.validate", return_value=None):
                        with patch.object(d, "_validate_ds", return_value=ds_state):
                            return d.validate("example.com")

    def test_ds_mismatch_is_bogus(self):
        """DS published at parent but matching no zone key = broken anchor = bogus."""
        result = self._validate_with_ds_state("mismatch")
        assert result["status"] == "bogus"
        assert result["dnskey_validated"] is True
        assert result["ds_validated"] is False

    def test_ds_absent_is_insecure(self):
        """Signed zone with no parent DS = unsigned delegation = insecure, not bogus."""
        result = self._validate_with_ds_state("absent")
        assert result["status"] == "insecure"
        assert result["dnskey_validated"] is True
        assert result["ds_validated"] is False

    def test_ds_query_error_defaults_insecure(self):
        """A DS lookup failure leaves status at the insecure default (unknown)."""
        result = self._validate_with_ds_state("error")
        assert result["status"] == "insecure"
        assert result["ds_validated"] is False

    def test_weak_algorithm_flagged(self):
        """RSASHA1 (algorithm 5) is surfaced in weak_algorithms."""
        result = self._validate_with_ds_state("match", algorithm=5)
        assert result["algorithms"] == [5]
        assert "RSASHA1" in result["weak_algorithms"]

    def test_dnskey_without_rrsig_is_bogus(self):
        d = DNSSEC()
        dnskey_rrset = [self._mock_key(13)]
        response = Mock()
        with patch.object(d, "_resolver_ad_flag", return_value=False):
            with patch.object(d, "_fetch_with_rrsig", return_value=response):
                with patch.object(
                    d, "_split_rrset_rrsig", return_value=(dnskey_rrset, None)
                ):
                    result = d.validate("example.com")

        assert result["status"] == "bogus"
        assert any("no RRSIG" in e for e in result["errors"])

    def test_weak_algorithms_table(self):
        """RSASHA1 variants and DSA are in the weak table; ECDSA is not."""
        assert 5 in WEAK_DNSSEC_ALGORITHMS
        assert 7 in WEAK_DNSSEC_ALGORITHMS
        assert 13 not in WEAK_DNSSEC_ALGORITHMS

    def test_inherits_from_base(self):
        from domain_profiler.base import Base
        assert isinstance(DNSSEC(), Base)
