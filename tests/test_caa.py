"""Tests for CAA issuance-policy analysis."""

from unittest.mock import patch

import dns.resolver

from domain_profiler.caa import CAA


def _rec(tag, value, flags=0):
    return {"flags": flags, "tag": tag, "value": value, "critical": bool(flags & 0x80)}


class TestCAA:
    """Test cases for the CAA class with mocked queries."""

    def test_no_caa_allows_any_ca(self):
        c = CAA()
        with patch.object(c, "_query_caa", return_value=[]):
            result = c.analyze("example.com")
        assert result["present"] is False
        assert result["allows_any_ca"] is True
        assert any("any CA may issue" in n for n in result["notes"])

    def test_issue_restricts_ca(self):
        c = CAA()
        records = [_rec("issue", "letsencrypt.org"), _rec("iodef", "mailto:a@x.com")]

        def fake_query(name):
            return records if name == "example.com" else []

        with patch.object(c, "_query_caa", side_effect=fake_query):
            result = c.analyze("example.com")

        assert result["present"] is True
        assert result["policy_domain"] == "example.com"
        assert result["issue"] == ["letsencrypt.org"]
        assert result["iodef"] == ["mailto:a@x.com"]
        assert result["allows_any_ca"] is False

    def test_tree_climb_finds_parent_policy(self):
        """A subdomain with no CAA inherits the apex policy (as a CA would)."""
        c = CAA()

        def fake_query(name):
            if name == "cloudflare.com":
                return [_rec("issue", "digicert.com")]
            return []  # www.cloudflare.com has none

        with patch.object(c, "_query_caa", side_effect=fake_query):
            result = c.analyze("www.cloudflare.com")

        assert result["present"] is True
        assert result["policy_domain"] == "cloudflare.com"
        assert result["issue"] == ["digicert.com"]

    def test_empty_issue_forbids_issuance(self):
        c = CAA()
        with patch.object(c, "_query_caa", return_value=[_rec("issue", ";")]):
            result = c.analyze("locked.example")
        assert result["forbids_issuance"] is True
        assert any("forbids all" in n for n in result["notes"])

    def test_missing_iodef_noted(self):
        c = CAA()
        with patch.object(c, "_query_caa", return_value=[_rec("issue", "letsencrypt.org")]):
            result = c.analyze("example.com")
        assert any("iodef" in n for n in result["notes"])

    def test_critical_unknown_tag_noted(self):
        c = CAA()
        with patch.object(c, "_query_caa", return_value=[_rec("weirdtag", "x", flags=0x80)]):
            result = c.analyze("example.com")
        assert any("critical" in n.lower() for n in result["notes"])

    def test_query_error_returns_none_and_notes(self):
        c = CAA()
        with patch.object(c, "_query_caa", return_value=None):
            result = c.analyze("example.com")
        # All labels error out → no policy found, notes record the errors.
        assert result["present"] is False
        assert any("query error" in n for n in result["notes"])

    def test_query_caa_handles_no_answer(self):
        """_query_caa returns [] (not None) for NoAnswer/NXDOMAIN."""
        c = CAA()
        with patch("dns.resolver.resolve", side_effect=dns.resolver.NoAnswer()):
            assert c._query_caa("example.com") == []

    def test_inherits_from_base(self):
        from domain_profiler.base import Base
        assert isinstance(CAA(), Base)
