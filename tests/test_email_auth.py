"""Tests for the email-authentication resolution functionality."""

import pytest
from unittest.mock import patch

from domain_profiler.email_auth import (
    EmailAuth,
    identify_mx_provider,
    is_queryable_domain,
    parse_bimi,
    parse_dkim,
    parse_dmarc,
    parse_mx_record,
    parse_spf,
    parse_spf_part,
    reconcile_dkim_wildcard,
)


class TestSpfParsing:
    """Test cases for SPF record parsing."""

    def test_parse_spf_part_default_qualifier(self):
        assert parse_spf_part("include:_spf.google.com") == {
            "qualifier": "+", "type": "include", "value": "_spf.google.com"
        }

    def test_parse_spf_part_explicit_qualifier(self):
        assert parse_spf_part("-all") == {"qualifier": "-", "type": "all", "value": None}
        assert parse_spf_part("~all") == {"qualifier": "~", "type": "all", "value": None}

    def test_parse_spf_part_redirect(self):
        assert parse_spf_part("redirect=example.com") == {
            "qualifier": "+", "type": "redirect", "value": "example.com"
        }

    def test_parse_spf_part_bare_a_mx(self):
        assert parse_spf_part("a")["type"] == "a"
        assert parse_spf_part("mx")["type"] == "mx"

    def test_parse_spf_part_unknown(self):
        assert parse_spf_part("garbage") == {"qualifier": "+", "type": "unknown", "value": "garbage"}

    def test_parse_spf_not_spf(self):
        assert parse_spf("google-site-verification=abc") is None

    def test_parse_spf_full_record(self):
        record = parse_spf("v=spf1 include:_spf.google.com ip4:1.2.3.4 ip6:2001:db8::1 -all")
        assert record is not None
        assert record["version"] == "spf1"
        assert record["includes"] == ["_spf.google.com"]
        assert record["ip4s"] == ["1.2.3.4"]
        assert record["ip6s"] == ["2001:db8::1"]
        assert record["all_qualifier"] == "-"


class TestDmarcParsing:
    def test_parse_dmarc_not_dmarc(self):
        assert parse_dmarc("v=spf1 -all") is None

    def test_parse_dmarc_full(self):
        record = parse_dmarc(
            "v=DMARC1; p=reject; sp=quarantine; rua=mailto:a@x.com,mailto:b@x.com; "
            "pct=50; adkim=s; aspf=r"
        )
        assert record["policy"] == "reject"
        assert record["subdomain_policy"] == "quarantine"
        assert record["rua"] == ["a@x.com", "b@x.com"]
        assert record["pct"] == 50
        assert record["adkim"] == "s"
        assert record["aspf"] == "r"

    def test_parse_dmarc_defaults(self):
        record = parse_dmarc("v=DMARC1; p=none")
        assert record["pct"] == 100
        assert record["subdomain_policy"] is None
        assert record["rua"] == []

    def test_parse_dmarc_pct_clamped(self):
        assert parse_dmarc("v=DMARC1; p=none; pct=250")["pct"] == 100
        assert parse_dmarc("v=DMARC1; p=none; pct=abc")["pct"] == 100

    def test_parse_dmarc_unknown_policy_becomes_none(self):
        assert parse_dmarc("v=DMARC1; p=bogus")["policy"] == "none"


class TestBimiParsing:
    def test_parse_bimi_full(self):
        record = parse_bimi("v=BIMI1; l=https://x.com/logo.svg; a=https://x.com/vmc.pem")
        assert record["logo_url"] == "https://x.com/logo.svg"
        assert record["authority_url"] == "https://x.com/vmc.pem"
        assert record["declined"] is False

    def test_parse_bimi_declined(self):
        record = parse_bimi("v=BIMI1; l=;")
        assert record["declined"] is True
        assert record["authority_url"] is None

    def test_parse_bimi_not_bimi(self):
        assert parse_bimi("v=spf1 -all") is None


class TestDkimParsing:
    def test_parse_dkim_valid(self):
        record = parse_dkim("v=DKIM1; k=rsa; p=MIGf...", "google")
        assert record["selector"] == "google"
        assert record["key_type"] == "rsa"
        assert record["public_key"] == "MIGf..."

    def test_parse_dkim_key_only(self):
        # Accepted when p= present even without v=DKIM1.
        assert parse_dkim("p=MIGf...", "sel") is not None

    def test_parse_dkim_revoked_empty_key(self):
        record = parse_dkim("v=DKIM1; p=", "sel")
        assert record["public_key"] == ""

    def test_parse_dkim_invalid(self):
        assert parse_dkim("just some text", "sel") is None

    def test_reconcile_wildcard_drops_echoes(self):
        found = [
            {"selector": "google", "raw": "v=DKIM1; p=REAL"},
            {"selector": "s1", "raw": "v=DKIM1; p=WILDCARD"},
        ]
        wildcard = {"selector": "probe", "raw": "v=DKIM1; p=WILDCARD"}
        result = reconcile_dkim_wildcard(found, wildcard)
        assert len(result) == 1
        assert result[0]["selector"] == "google"

    def test_reconcile_wildcard_none_passthrough(self):
        found = [{"selector": "google", "raw": "x"}]
        assert reconcile_dkim_wildcard(found, None) == found


class TestMxParsing:
    def test_parse_mx_record(self):
        record = parse_mx_record("10 aspmx.l.google.com.")
        assert record["priority"] == 10
        assert record["hostname"] == "aspmx.l.google.com"
        assert record["provider"] == "Google Workspace"

    def test_parse_mx_record_bad_priority(self):
        assert parse_mx_record("x mail.example.com")["priority"] == 0

    def test_identify_mx_provider(self):
        assert identify_mx_provider("foo.mail.protection.outlook.com") == "Microsoft 365"
        assert identify_mx_provider("inbound-smtp.us-east-1.amazonaws.com") == "Amazon SES"
        assert identify_mx_provider("mail.unknown-host.net") is None


class TestIsQueryableDomain:
    @pytest.mark.parametrize("domain,expected", [
        ("example.com", True),
        ("_spf.google.com", True),
        ("sub.example.com.", True),
        ("nodot", False),
        ("", False),
        ("a." + "b" * 64 + ".com", False),  # label too long
    ])
    def test_is_queryable_domain(self, domain, expected):
        assert is_queryable_domain(domain) is expected


class TestEmailAuthResolution:
    """Test cases for the EmailAuth class using a fake resolver."""

    def _make_resolver(self, records):
        """Build a fake self._query backed by a {(name, type): [values]} map."""
        def fake_query(name, record_type):
            key = (name, record_type)
            if key in records:
                return (True, list(records[key]))
            return (False, [])
        return fake_query

    def test_selector_set_prefers_explicit_selector(self):
        ea = EmailAuth()
        selectors = ea._build_selector_set("myselector")
        assert selectors[0] == "myselector"
        assert len(selectors) <= ea.MAX_DKIM_SELECTORS

    def test_selector_set_rejects_invalid_selector(self):
        ea = EmailAuth()
        selectors = ea._build_selector_set("bad selector!")
        assert selectors[0] == "google"  # invalid ignored, common list used

    def test_resolve_spf_flattens_includes(self):
        ea = EmailAuth()
        records = {
            ("_spf.child.com", "TXT"): ["v=spf1 ip4:5.6.7.8 -all"],
        }
        with patch.object(ea, "_query", side_effect=self._make_resolver(records)):
            root = parse_spf("v=spf1 ip4:1.2.3.4 include:_spf.child.com -all")
            resolution = ea.resolve_spf("parent.com", root)

        assert "1.2.3.4" in resolution["flattened"]["ip4"]
        assert "5.6.7.8" in resolution["flattened"]["ip4"]
        assert resolution["flattened"]["lookup_count"] == 1
        assert resolution["flattened"]["lookup_limit_exceeded"] is False

    def test_resolve_spf_loop_guard(self):
        ea = EmailAuth()
        # a.com includes b.com, b.com includes a.com.
        records = {
            ("b.com", "TXT"): ["v=spf1 include:a.com -all"],
        }
        with patch.object(ea, "_query", side_effect=self._make_resolver(records)):
            root = parse_spf("v=spf1 include:b.com -all")
            resolution = ea.resolve_spf("a.com", root)

        # The loop back to a.com is avoided, not infinitely recursed.
        b_node = resolution["tree"]["children"][0]
        a_again = b_node["children"][0]
        assert a_again["error"] == "Already resolved (loop avoided)"

    def test_resolve_spf_lookup_limit(self):
        ea = EmailAuth()
        # 11 includes; the 11th must exceed the RFC 10-lookup budget.
        includes = " ".join(f"include:c{i}.com" for i in range(11))
        records = {}
        with patch.object(ea, "_query", side_effect=self._make_resolver(records)):
            root = parse_spf(f"v=spf1 {includes} -all")
            resolution = ea.resolve_spf("root.com", root)

        assert resolution["flattened"]["lookup_limit_exceeded"] is True
        assert resolution["flattened"]["lookup_count"] == 10

    def test_lookup_dkim_filters_wildcard(self):
        ea = EmailAuth()

        def fake_query_selector(domain, selector):
            if selector == "google":
                return {"selector": "google", "raw": "v=DKIM1; p=REAL"}
            if selector.startswith("wildcard-probe-"):
                return {"selector": selector, "raw": "v=DKIM1; p=CATCHALL"}
            # Every other selector echoes the wildcard.
            return {"selector": selector, "raw": "v=DKIM1; p=CATCHALL"}

        with patch.object(ea, "_query_dkim_selector", side_effect=fake_query_selector):
            result = ea.lookup_dkim("example.com")

        raws = [r["raw"] for r in result["records"]]
        assert "v=DKIM1; p=REAL" in raws
        assert "v=DKIM1; p=CATCHALL" not in raws
        assert result["wildcard"]["selector"] == "*"

    def test_get_report_structure(self):
        ea = EmailAuth()
        records = {
            ("example.com", "TXT"): ["v=spf1 ip4:1.2.3.4 -all"],
            ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject"],
            ("default._bimi.example.com", "TXT"): ["v=BIMI1; l=https://x/logo.svg"],
            ("example.com", "MX"): ["10 aspmx.l.google.com."],
        }
        with patch.object(ea, "_query", side_effect=self._make_resolver(records)):
            with patch.object(ea, "lookup_dkim", return_value={"records": [], "checked_selectors": [], "wildcard": None}):
                report = ea.get_report("example.com")

        assert report["domain"] == "example.com"
        assert report["spf"]["ip4s"] == ["1.2.3.4"]
        assert report["spf_flattened"]["ip4"] == ["1.2.3.4"]
        assert report["dmarc"]["policy"] == "reject"
        assert report["bimi"]["logo_url"] == "https://x/logo.svg"
        assert report["mx_records"][0]["provider"] == "Google Workspace"

    def test_email_auth_inherits_from_base(self):
        from domain_profiler.base import Base
        assert isinstance(EmailAuth(), Base)
