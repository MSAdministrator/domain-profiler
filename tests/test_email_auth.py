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

    def test_parse_spf_part_exact_dicts_all_forms(self):
        """Full-dict assertions for every mechanism form (kills key/value mutants)."""
        assert parse_spf_part("exp=explain.example.com") == {
            "qualifier": "+", "type": "exp", "value": "explain.example.com"
        }
        assert parse_spf_part("ip4:1.2.3.4") == {
            "qualifier": "+", "type": "ip4", "value": "1.2.3.4"
        }
        assert parse_spf_part("ip6:2001:db8::1") == {
            "qualifier": "+", "type": "ip6", "value": "2001:db8::1"
        }
        assert parse_spf_part("?ptr") == {"qualifier": "?", "type": "ptr", "value": None}
        assert parse_spf_part("exists:%{i}.example.com") == {
            "qualifier": "+", "type": "exists", "value": "%{i}.example.com"
        }
        assert parse_spf_part("a/24") == {"qualifier": "+", "type": "a", "value": "a/24"}
        assert parse_spf_part("mx/24") == {"qualifier": "+", "type": "mx", "value": "mx/24"}

    def test_parse_spf_part_all_qualifiers(self):
        for q in ("+", "-", "~", "?"):
            assert parse_spf_part(f"{q}all") == {"qualifier": q, "type": "all", "value": None}

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

    def test_parse_dmarc_full_dict(self):
        raw = "v=DMARC1; p=quarantine; ruf=mailto:f@x.com"
        assert parse_dmarc(raw) == {
            "version": "DMARC1",
            "policy": "quarantine",
            "subdomain_policy": None,
            "rua": [],
            "ruf": ["f@x.com"],
            "pct": 100,
            "adkim": "r",
            "aspf": "r",
            "raw": raw,
        }

    def test_parse_dmarc_adkim_aspf_relaxed_default(self):
        # Anything other than exactly "s" is "r".
        rec = parse_dmarc("v=DMARC1; p=none; adkim=x; aspf=x")
        assert rec["adkim"] == "r"
        assert rec["aspf"] == "r"

    def test_parse_dmarc_invalid_policy_falls_back_none(self):
        assert parse_dmarc("v=DMARC1; p=bogus")["policy"] == "none"

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

    def test_parse_bimi_full_dict(self):
        raw = "v=BIMI1; l=https://x.com/logo.svg; a=https://x.com/vmc.pem"
        assert parse_bimi(raw, "default") == {
            "selector": "default",
            "version": "BIMI1",
            "logo_url": "https://x.com/logo.svg",
            "authority_url": "https://x.com/vmc.pem",
            "declined": False,
            "raw": raw,
        }

    def test_parse_bimi_selector_passthrough(self):
        assert parse_bimi("v=BIMI1; l=x", "brand")["selector"] == "brand"

    def test_parse_bimi_case_insensitive_version(self):
        assert parse_bimi("v=bimi1; l=x") is not None


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

    def test_parse_dkim_full_dict(self):
        """Every field asserted (kills key/value + default mutants)."""
        raw = "v=DKIM1; k=ed25519; p=KEY; s=email; t=y"
        assert parse_dkim(raw, "sel1") == {
            "selector": "sel1",
            "version": "DKIM1",
            "key_type": "ed25519",
            "public_key": "KEY",
            "service_type": "email",
            "flags": "y",
            "raw": raw,
        }

    def test_parse_dkim_defaults_when_tags_absent(self):
        """version defaults DKIM1, key_type rsa, optional tags None."""
        rec = parse_dkim("p=ABC", "sel")
        assert rec["version"] == "DKIM1"
        assert rec["key_type"] == "rsa"
        assert rec["service_type"] is None
        assert rec["flags"] is None

    def test_parse_dkim_case_insensitive_version_and_key(self):
        # v=dkim1 (lowercase) and V= must still be recognized (regex IGNORECASE).
        assert parse_dkim("v=dkim1; p=X", "s") is not None
        assert parse_dkim("V=DKIM1; p=X", "s") is not None
        # A bare p= with any casing is accepted.
        assert parse_dkim("P=X", "s") is not None

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

    def test_root_node_shape_and_values(self):
        """Assert the root node's keys/values (kills node-dict key/kind mutants)."""
        ea = EmailAuth()
        with patch.object(ea, "_query", side_effect=self._make_resolver({})):
            root = parse_spf("v=spf1 ip4:1.2.3.4 -all")
            tree = ea.resolve_spf("root.com", root)["tree"]
        assert tree["domain"] == "root.com"
        assert tree["kind"] == "root"
        assert tree["record"] is root
        assert tree["error"] is None
        assert tree["hosts"] == []
        assert tree["children"] == []

    def test_no_spf_record_node_error(self):
        """A child with no SPF record carries the exact 'No SPF record found' error."""
        ea = EmailAuth()
        # include target returns no SPF → child node gets the error string.
        with patch.object(ea, "_query", side_effect=self._make_resolver({})):
            root = parse_spf("v=spf1 include:missing.com -all")
            tree = ea.resolve_spf("root.com", root)["tree"]
        child = tree["children"][0]
        assert child["kind"] == "include"
        assert child["domain"] == "missing.com"
        assert child["error"] == "No SPF record found"

    def test_a_mechanism_records_host_entry(self):
        """An `a` mechanism consumes a lookup and appends a host entry."""
        ea = EmailAuth()

        def fake_query(name, rtype):
            if rtype == "A":
                return (True, ["1.1.1.1"])
            return (False, [])

        with patch.object(ea, "_query", side_effect=fake_query):
            root = parse_spf("v=spf1 a -all")
            res = ea.resolve_spf("host.com", root)
        host_entry = res["tree"]["hosts"][0]
        assert host_entry["kind"] == "a"
        assert host_entry["host"] == "host.com"  # bare `a` uses the node domain
        assert host_entry["ip4"] == ["1.1.1.1"]
        assert res["flattened"]["lookup_count"] == 1

    def test_ptr_and_exists_consume_lookups_only(self):
        """ptr/exists consume a lookup budget but add no hosts/IPs."""
        ea = EmailAuth()
        with patch.object(ea, "_query", side_effect=self._make_resolver({})):
            root = parse_spf("v=spf1 ptr exists:%{i}.x.com -all")
            res = ea.resolve_spf("host.com", root)
        assert res["tree"]["hosts"] == []
        assert res["flattened"]["ip4"] == []
        assert res["flattened"]["lookup_count"] == 2  # ptr + exists

    def test_depth_limit_error(self):
        """Exceeding MAX_DEPTH yields the exact depth error, not infinite recursion."""
        import domain_profiler.email_auth as ea_mod
        ea = EmailAuth()
        with patch.object(ea_mod, "MAX_DEPTH", 0):
            with patch.object(ea, "_query", side_effect=self._make_resolver(
                {("child.com", "TXT"): ["v=spf1 ip4:1.2.3.4 -all"]}
            )):
                root = parse_spf("v=spf1 include:child.com -all")
                tree = ea.resolve_spf("root.com", root)["tree"]
        assert tree["children"][0]["error"] == "Maximum include depth exceeded"

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


class TestQueryAndRdata:
    """Cover _query and _rdata_to_string (previously no-coverage)."""

    def test_query_returns_ok_and_values(self):
        import domain_profiler.email_auth as ea_mod
        r1 = _FakeRdata("1.2.3.4")
        with patch.object(ea_mod.resolver, "query", return_value=[r1]) as mq:
            ok, values = EmailAuth()._query("example.com", "A")
        assert ok is True
        assert values == ["1.2.3.4"]
        # Contract: name, record type, and timeout are passed through.
        args, kwargs = mq.call_args
        assert args[0] == "example.com"
        assert args[1] == "A"
        assert kwargs["lifetime"] == EmailAuth.QUERY_TIMEOUT

    def test_query_failure_returns_false_empty(self):
        import domain_profiler.email_auth as ea_mod
        with patch.object(ea_mod.resolver, "query", side_effect=Exception("SERVFAIL")):
            ok, values = EmailAuth()._query("example.com", "A")
        assert ok is False
        assert values == []

    def test_rdata_to_string_txt_concatenates_strings(self):
        from domain_profiler.email_auth import _rdata_to_string
        rdata = _FakeTxtRdata([b"v=spf1 ", b"ip4:1.2.3.4 -all"])
        # TXT uses .strings and joins with no separator (RFC 7208 §3.3).
        assert _rdata_to_string(rdata, "TXT") == "v=spf1 ip4:1.2.3.4 -all"

    def test_rdata_to_string_non_txt_uses_to_text(self):
        from domain_profiler.email_auth import _rdata_to_string
        assert _rdata_to_string(_FakeRdata("10 mx.example."), "MX") == "10 mx.example."


class TestResolveAddresses:
    """Cover _resolve_addresses (no-coverage): A/AAAA flatten into ctx + result."""

    def _ctx(self):
        return {"ip4": set(), "ip6": set()}

    def test_collects_a_and_aaaa(self):
        ea = EmailAuth()
        ctx = self._ctx()

        def fake_query(host, rtype):
            return (True, ["1.2.3.4"]) if rtype == "A" else (True, ["2001:db8::1"])

        with patch.object(ea, "_query", side_effect=fake_query):
            out = ea._resolve_addresses("mail.example.com", ctx)
        assert out == {"ip4": ["1.2.3.4"], "ip6": ["2001:db8::1"]}
        assert ctx["ip4"] == {"1.2.3.4"}
        assert ctx["ip6"] == {"2001:db8::1"}

    def test_invalid_host_short_circuits(self):
        ea = EmailAuth()
        with patch.object(ea, "_query") as mq:
            out = ea._resolve_addresses("nodot", self._ctx())
        assert out == {"ip4": [], "ip6": []}
        mq.assert_not_called()  # invalid domain never queried


class TestResolveMx:
    """Cover _resolve_mx (no-coverage): MX host parse + address flatten."""

    def test_mx_hosts_resolved_and_deduped(self):
        ea = EmailAuth()
        ctx = {"ip4": set(), "ip6": set()}

        def fake_query(host, rtype):
            if rtype == "MX":
                return (True, ["10 mx1.example.com.", "20 mx2.example.com."])
            return (False, [])

        # Both MX hosts resolve to the same IP → deduped.
        def fake_addrs(host, ctx):
            return {"ip4": ["9.9.9.9"], "ip6": []}

        with patch.object(ea, "_query", side_effect=fake_query):
            with patch.object(ea, "_resolve_addresses", side_effect=fake_addrs):
                out = ea._resolve_mx("example.com", ctx)
        assert out["ip4"] == ["9.9.9.9"]  # deduped from two hosts

    def test_mx_query_failure_returns_empty(self):
        ea = EmailAuth()
        with patch.object(ea, "_query", return_value=(False, [])):
            out = ea._resolve_mx("example.com", {"ip4": set(), "ip6": set()})
        assert out == {"ip4": [], "ip6": []}


class TestQueryDkimSelector:
    """Cover _query_dkim_selector (no-coverage)."""

    def test_builds_domainkey_name_and_parses(self):
        ea = EmailAuth()
        with patch.object(ea, "_query", return_value=(True, ["v=DKIM1; p=ABC"])) as mq:
            rec = ea._query_dkim_selector("example.com", "google")
        mq.assert_called_once_with("google._domainkey.example.com", "TXT")
        assert rec["selector"] == "google"
        assert rec["public_key"] == "ABC"

    def test_no_record_returns_none(self):
        ea = EmailAuth()
        with patch.object(ea, "_query", return_value=(False, [])):
            assert ea._query_dkim_selector("example.com", "google") is None


class _FakeRdata:
    def __init__(self, text):
        self._text = text

    def to_text(self):
        return self._text


class _FakeTxtRdata:
    def __init__(self, strings):
        self.strings = strings
