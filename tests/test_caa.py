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

    def test_nonempty_issue_does_not_forbid_issuance(self):
        """A real CA in `issue` must NOT set forbids_issuance (kills and->or)."""
        c = CAA()
        with patch.object(c, "_query_caa", return_value=[_rec("issue", "letsencrypt.org")]):
            result = c.analyze("example.com")
        assert result["forbids_issuance"] is False

    def test_query_error_then_policy_lower_is_still_found(self):
        """An errored FQDN label must not abort the climb (kills continue->break)."""
        c = CAA()

        def fake(name):
            if name == "a.example.com":
                return None  # transient error at the first label
            if name == "example.com":
                return [_rec("issue", "digicert.com")]
            return []

        with patch.object(c, "_query_caa", side_effect=fake):
            r = c.analyze("a.example.com")
        # The climb continued past the errored label and found the apex policy.
        assert r["present"] is True
        assert r["policy_domain"] == "example.com"
        assert r["issue"] == ["digicert.com"]

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

    def test_all_queries_error_is_unknown_not_open(self):
        c = CAA()
        with patch.object(c, "_query_caa", return_value=None):
            result = c.analyze("example.com")
        # All labels error out → policy is unknown, not "any CA may issue".
        assert result["present"] is False
        assert result["policy_unknown"] is True
        assert result["allows_any_ca"] is False
        assert any("could not be determined" in n for n in result["notes"])

    def test_authoritative_no_caa_allows_any_ca(self):
        """A clean NoAnswer (not an error) means the absence is real."""
        c = CAA()
        with patch.object(c, "_query_caa", return_value=[]):
            result = c.analyze("example.com")
        assert result["policy_unknown"] is False
        assert result["allows_any_ca"] is True
        assert any("any CA may issue" in n for n in result["notes"])

    def test_query_caa_handles_no_answer(self):
        """_query_caa returns [] (not None) for NoAnswer/NXDOMAIN."""
        c = CAA()
        with patch("dns.resolver.resolve", side_effect=dns.resolver.NoAnswer()):
            assert c._query_caa("example.com") == []

    def test_inherits_from_base(self):
        from domain_profiler.base import Base
        assert isinstance(CAA(), Base)


class _FakeCaaRdata:
    """Minimal stand-in for a dnspython CAA rdata object."""

    def __init__(self, flags, tag, value):
        self.flags = flags
        self.tag = tag
        self.value = value


class TestQueryCaaRealParsing:
    """Exercise the real _query_caa parsing (not a mock of the method)."""

    def test_parses_bytes_tag_and_value(self):
        """bytes tag/value are decoded; flags/critical computed from the rdata."""
        c = CAA()
        rdata = _FakeCaaRdata(flags=0, tag=b"issue", value=b"letsencrypt.org")
        with patch("dns.resolver.resolve", return_value=[rdata]):
            records = c._query_caa("example.com")
        assert records == [
            {"flags": 0, "tag": "issue", "value": "letsencrypt.org", "critical": False}
        ]

    def test_parses_str_tag_and_value(self):
        """str tag/value pass through without decoding."""
        c = CAA()
        rdata = _FakeCaaRdata(flags=0, tag="iodef", value="mailto:a@x.com")
        with patch("dns.resolver.resolve", return_value=[rdata]):
            records = c._query_caa("example.com")
        assert records[0]["tag"] == "iodef"
        assert records[0]["value"] == "mailto:a@x.com"

    def test_critical_flag_bit_set(self):
        """The 0x80 issuer-critical bit sets critical=True and preserves flags."""
        c = CAA()
        rdata = _FakeCaaRdata(flags=128, tag="issue", value="ca.example")
        with patch("dns.resolver.resolve", return_value=[rdata]):
            records = c._query_caa("example.com")
        assert records[0]["flags"] == 128
        assert records[0]["critical"] is True

    def test_non_critical_flag(self):
        c = CAA()
        rdata = _FakeCaaRdata(flags=0, tag="issue", value="ca.example")
        with patch("dns.resolver.resolve", return_value=[rdata]):
            records = c._query_caa("example.com")
        assert records[0]["critical"] is False

    def test_multiple_records_all_parsed(self):
        c = CAA()
        rdatas = [
            _FakeCaaRdata(0, b"issue", b"a.example"),
            _FakeCaaRdata(0, b"issuewild", b"b.example"),
        ]
        with patch("dns.resolver.resolve", return_value=rdatas):
            records = c._query_caa("example.com")
        assert [r["tag"] for r in records] == ["issue", "issuewild"]
        assert [r["value"] for r in records] == ["a.example", "b.example"]

    def test_generic_exception_returns_none(self):
        """A transient resolver error returns None (distinct from [] NoAnswer)."""
        c = CAA()
        with patch("dns.resolver.resolve", side_effect=RuntimeError("SERVFAIL")):
            assert c._query_caa("example.com") is None

    def test_nxdomain_returns_empty(self):
        c = CAA()
        with patch("dns.resolver.resolve", side_effect=dns.resolver.NXDOMAIN()):
            assert c._query_caa("example.com") == []

    def test_resolve_called_with_name_caa_type_and_timeout(self):
        """The resolver call contract: the given name, CAA rdatatype, and timeout."""
        import dns.rdatatype
        c = CAA()
        with patch("dns.resolver.resolve", return_value=[]) as mock_resolve:
            c._query_caa("example.com")
        args, kwargs = mock_resolve.call_args
        assert args[0] == "example.com"
        assert args[1] == dns.rdatatype.CAA
        assert kwargs.get("lifetime") == c.QUERY_TIMEOUT


class TestAnalyzeResultShape:
    """Assert result-dict keys/values by name (kills key-rename mutants)."""

    def test_result_keys_present(self):
        c = CAA()
        with patch.object(c, "_query_caa", return_value=[_rec("issue", "letsencrypt.org")]):
            r = c.analyze("example.com")
        for key in (
            "domain", "present", "policy_domain", "records", "issue",
            "issuewild", "iodef", "allows_any_ca", "forbids_issuance",
            "policy_unknown", "notes",
        ):
            assert key in r, f"missing key {key}"

    def test_domain_and_policy_domain_values(self):
        c = CAA()

        def fake(name):
            return [_rec("issue", "digicert.com")] if name == "example.com" else []

        with patch.object(c, "_query_caa", side_effect=fake):
            r = c.analyze("example.com")
        assert r["domain"] == "example.com"
        assert r["policy_domain"] == "example.com"
        assert r["present"] is True

    def test_issue_and_issuewild_and_iodef_split(self):
        c = CAA()
        recs = [
            _rec("issue", "a.example"),
            _rec("issuewild", "b.example"),
            _rec("iodef", "mailto:x@y.com"),
        ]
        with patch.object(c, "_query_caa", return_value=recs):
            r = c.analyze("example.com")
        assert r["issue"] == ["a.example"]
        assert r["issuewild"] == ["b.example"]
        assert r["iodef"] == ["mailto:x@y.com"]
        assert r["allows_any_ca"] is False

    def test_no_record_result_keeps_defaults(self):
        """With no CAA anywhere, defaults survive by name/value (kills key renames)."""
        c = CAA()
        with patch.object(c, "_query_caa", return_value=[]):
            r = c.analyze("example.com")
        assert r["present"] is False
        assert r["policy_domain"] is None
        assert r["records"] == []
        assert r["issue"] == []
        assert r["issuewild"] == []
        assert r["iodef"] == []
        assert r["forbids_issuance"] is False
        assert r["allows_any_ca"] is True

    def test_tree_climb_queries_expected_labels_in_order(self):
        """Climb queries a.b.example.com, then b.example.com, then example.com."""
        c = CAA()
        queried: list[str] = []

        def fake(name):
            queried.append(name)
            return []  # nothing found anywhere

        with patch.object(c, "_query_caa", side_effect=fake):
            c.analyze("a.b.example.com")
        # range(len(labels)-1) climbs every label down to the TLD but stops
        # before the empty root label; an off-by-one either appends the root
        # "" query or drops the TLD.
        assert queried == ["a.b.example.com", "b.example.com", "example.com", "com"]

    def test_tree_climb_stops_at_first_match(self):
        """Once a label has CAA, higher labels are not queried."""
        c = CAA()
        queried: list[str] = []

        def fake(name):
            queried.append(name)
            return [_rec("issue", "ca.example")] if name == "b.example.com" else []

        with patch.object(c, "_query_caa", side_effect=fake):
            r = c.analyze("a.b.example.com")
        assert r["policy_domain"] == "b.example.com"
        assert queried == ["a.b.example.com", "b.example.com"]  # example.com never queried
