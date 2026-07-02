"""Tests for wildcard DNS detection and subdomain-takeover checks."""

from unittest.mock import patch

import dns.rdatatype

from domain_profiler.takeover import Takeover, TAKEOVER_PRONE_PROVIDERS


class TestWildcard:
    def test_no_wildcard(self):
        t = Takeover()
        # Both random probes NXDOMAIN → ("nxdomain", []) → empty sets.
        with patch.object(t, "_resolve", return_value=("nxdomain", [])):
            result = t.detect_wildcard("example.com")
        assert result["wildcard"] is False
        assert result["addresses"] == []

    def test_wildcard_detected(self):
        t = Takeover()
        # Both random labels resolve to the same synthesized IP set.
        with patch.object(t, "_resolve", return_value=("ok", ["185.199.108.153"])):
            result = t.detect_wildcard("github.io")
        assert result["wildcard"] is True
        assert result["addresses"] == ["185.199.108.153"]

    def test_wildcard_requires_matching_probes(self):
        t = Takeover()
        # Different answers per probe → not a wildcard.
        responses = [("ok", ["1.1.1.1"]), ("ok", ["2.2.2.2"])]
        with patch.object(t, "_resolve", side_effect=responses):
            result = t.detect_wildcard("example.com")
        assert result["wildcard"] is False


class TestProviderMatch:
    def test_match_provider_suffix(self):
        assert Takeover._match_provider("foo.s3.amazonaws.com") == "AWS S3"
        assert Takeover._match_provider("x.github.io") == "GitHub Pages"

    def test_match_provider_none(self):
        assert Takeover._match_provider("mail.example.com") is None

    def test_provider_table_nonempty(self):
        assert "github.io" in TAKEOVER_PRONE_PROVIDERS


class TestSubdomainCheck:
    def test_no_cname_no_risk(self):
        t = Takeover()
        with patch.object(t, "_resolve", return_value=("noanswer", [])):
            r = t.check_subdomain("www.example.com")
        assert r["risk"] == "none"
        assert r["cname"] is None

    def test_dangling_cname_to_provider_is_high(self):
        t = Takeover()

        def fake_resolve(name, rdtype):
            if rdtype == dns.rdatatype.CNAME:
                return ("ok", ["myapp.s3.amazonaws.com."])
            return ("nxdomain", [])  # target NXDOMAIN

        with patch.object(t, "_resolve", side_effect=fake_resolve):
            r = t.check_subdomain("assets.example.com")

        assert r["provider"] == "AWS S3"
        assert r["dangling"] is True
        assert r["risk"] == "high"

    def test_dangling_cname_unknown_provider_is_medium(self):
        t = Takeover()

        def fake_resolve(name, rdtype):
            if rdtype == dns.rdatatype.CNAME:
                return ("ok", ["gone.internal-thing.net."])
            return ("nxdomain", [])

        with patch.object(t, "_resolve", side_effect=fake_resolve):
            r = t.check_subdomain("old.example.com")

        assert r["dangling"] is True
        assert r["risk"] == "medium"

    def test_transient_error_is_not_dangling(self):
        """A SERVFAIL/timeout on the target must NOT be reported as a takeover."""
        t = Takeover()

        def fake_resolve(name, rdtype):
            if rdtype == dns.rdatatype.CNAME:
                return ("ok", ["myapp.s3.amazonaws.com."])
            return ("error", [])  # transient resolution failure

        with patch.object(t, "_resolve", side_effect=fake_resolve):
            r = t.check_subdomain("assets.example.com")

        assert r["dangling"] is False
        assert r["risk"] != "high"
        assert any("transient" in n for n in r["notes"])

    def test_live_cname_to_provider_is_low(self):
        t = Takeover()

        def fake_resolve(name, rdtype):
            if rdtype == dns.rdatatype.CNAME:
                return ("ok", ["myapp.herokuapp.com."])
            return ("ok", ["1.2.3.4"])  # target resolves

        with patch.object(t, "_resolve", side_effect=fake_resolve):
            r = t.check_subdomain("app.example.com")

        assert r["provider"] == "Heroku"
        assert r["dangling"] is False
        assert r["risk"] == "low"

    def test_report_structure(self):
        t = Takeover()
        with patch.object(t, "detect_wildcard", return_value={"wildcard": False, "addresses": []}):
            with patch.object(t, "check_subdomain", return_value={"risk": "none"}):
                report = t.report("example.com", ["a.example.com"])
        assert report["domain"] == "example.com"
        assert "wildcard" in report
        assert len(report["subdomains"]) == 2  # apex + provided sub

    def test_inherits_from_base(self):
        from domain_profiler.base import Base
        assert isinstance(Takeover(), Base)
