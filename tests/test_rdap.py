"""Tests for RDAP parsing."""

from unittest.mock import patch

import requests

from domain_profiler.rdap import RDAP


SAMPLE_RDAP = {
    "objectClassName": "domain",
    "ldhName": "GOOGLE.COM",
    "handle": "2138514_DOMAIN_COM-VRSN",
    "status": ["client delete prohibited", "client transfer prohibited"],
    "events": [
        {"eventAction": "registration", "eventDate": "1997-09-15T04:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2028-09-14T04:00:00Z"},
        {"eventAction": "last changed", "eventDate": "2019-09-09T15:39:04Z"},
    ],
    "entities": [
        {
            "roles": ["registrar"],
            "publicIds": [{"type": "IANA Registrar ID", "identifier": "292"}],
            "vcardArray": [
                "vcard",
                [
                    ["version", {}, "text", "4.0"],
                    ["fn", {}, "text", "MarkMonitor Inc."],
                ],
            ],
        }
    ],
    "nameservers": [
        {"ldhName": "NS1.GOOGLE.COM"},
        {"ldhName": "NS2.GOOGLE.COM"},
    ],
    "secureDNS": {"delegationSigned": False},
}


class TestRDAPParsing:
    def test_parse_domain_extracts_fields(self):
        result = RDAP().parse_domain(SAMPLE_RDAP)
        assert result["domain"] == "GOOGLE.COM"
        assert result["registrar"] == "MarkMonitor Inc."
        assert result["registrar_iana_id"] == "292"
        assert result["registered"] == "1997-09-15T04:00:00Z"
        assert result["expires"] == "2028-09-14T04:00:00Z"
        assert result["last_changed"] == "2019-09-09T15:39:04Z"
        assert result["nameservers"] == ["NS1.GOOGLE.COM", "NS2.GOOGLE.COM"]
        assert result["dnssec_delegated"] is False
        assert result["error"] is None

    def test_parse_domain_dnssec_signed(self):
        raw = dict(SAMPLE_RDAP, secureDNS={"delegationSigned": True})
        assert RDAP().parse_domain(raw)["dnssec_delegated"] is True

    def test_parse_domain_missing_registrar(self):
        raw = dict(SAMPLE_RDAP, entities=[])
        result = RDAP().parse_domain(raw)
        assert result["registrar"] is None
        assert result["registrar_iana_id"] is None

    def test_parse_domain_error_object(self):
        result = RDAP().parse_domain({"errorCode": 404, "title": "Not found"})
        assert result["error"] is not None

    def test_report_delegates_to_parse(self):
        with patch.object(RDAP, "domain", return_value=SAMPLE_RDAP):
            result = RDAP().report("google.com")
        assert result["registrar"] == "MarkMonitor Inc."

    def test_report_handles_network_error(self):
        with patch.object(RDAP, "domain", side_effect=Exception("boom")):
            result = RDAP().report("google.com")
        # Exact keys on the failure dict (kills "domain"/"error" key-rename mutants).
        assert result["domain"] == "google.com"
        assert "failed" in result["error"]

    def test_report_parse_failure_shape(self):
        with patch.object(RDAP, "domain", return_value={"bad": True}):
            with patch.object(RDAP, "parse_domain", side_effect=Exception("nope")):
                result = RDAP().report("google.com")
        assert result["domain"] == "google.com"
        assert result["error"].startswith("RDAP parse failed")

    def test_report_handles_http_404_with_friendly_message(self):
        response = requests.Response()
        response.status_code = 404
        response.url = "https://www.rdap.net/domain/example.it"
        err = requests.HTTPError("404 Client Error", response=response)
        with patch.object(RDAP, "domain", side_effect=err):
            result = RDAP().report("example.it")
        assert result["domain"] == "example.it"
        assert "not found" in result["error"].lower()
        assert "https://www.rdap.net/domain/example.it" in result["error"]

    def test_report_handles_http_non_404_status(self):
        response = requests.Response()
        response.status_code = 500
        err = requests.HTTPError("500 Server Error", response=response)
        with patch.object(RDAP, "domain", side_effect=err):
            result = RDAP().report("example.com")
        assert result["domain"] == "example.com"
        assert result["error"].startswith("RDAP HTTP error (500)")

    def test_parse_whois_domain_normalizes_fields(self):
        raw = {
            "domain_name": ["EXAMPLE.IT"],
            "registrar": ["Registrar SpA"],
            "creation_date": "2020-01-01T00:00:00Z",
            "expiration_date": None,
            "updated_date": ["2024-01-01T00:00:00Z"],
            "status": "ok",
            "name_servers": {"NS2.EXAMPLE.IT", "NS1.EXAMPLE.IT"},
        }
        result = RDAP().parse_whois_domain(raw, "example.it")
        assert result == {
            "domain": "EXAMPLE.IT",
            "handle": None,
            "registrar": "Registrar SpA",
            "registrar_iana_id": None,
            "registered": "2020-01-01T00:00:00Z",
            "expires": None,
            "last_changed": "2024-01-01T00:00:00Z",
            "statuses": ["ok"],
            "nameservers": ["NS1.EXAMPLE.IT", "NS2.EXAMPLE.IT"],
            "dnssec_delegated": None,
            "error": None,
            "source": "whois",
        }

    def test_parse_whois_domain_splits_multiline_nameservers(self):
        raw = {
            "domain_name": "example.it",
            "name_servers": "ns1.example.it\nns2.example.it",
        }
        result = RDAP().parse_whois_domain(raw, "example.it")
        assert result["nameservers"] == ["ns1.example.it", "ns2.example.it"]

    def test_vcard_field_org_fallback(self):
        raw = dict(
            SAMPLE_RDAP,
            entities=[
                {
                    "roles": ["registrar"],
                    "vcardArray": [
                        "vcard",
                        [["org", {}, "text", "Some Registrar LLC"]],
                    ],
                }
            ],
        )
        assert RDAP().parse_domain(raw)["registrar"] == "Some Registrar LLC"

    def test_inherits_from_base(self):
        from domain_profiler.base import Base
        assert isinstance(RDAP(), Base)


class TestParseDomainStrictFields:
    """Assert every parsed field by key+value (kills key-rename / get()-key mutants)."""

    def test_all_fields_exact(self):
        r = RDAP().parse_domain(SAMPLE_RDAP)
        assert r == {
            "domain": "GOOGLE.COM",
            "handle": "2138514_DOMAIN_COM-VRSN",
            "registrar": "MarkMonitor Inc.",
            "registrar_iana_id": "292",
            "registered": "1997-09-15T04:00:00Z",
            "expires": "2028-09-14T04:00:00Z",
            "last_changed": "2019-09-09T15:39:04Z",
            "statuses": ["client delete prohibited", "client transfer prohibited"],
            "nameservers": ["NS1.GOOGLE.COM", "NS2.GOOGLE.COM"],
            "dnssec_delegated": False,
            "error": None,
        }

    def test_statuses_default_empty_when_absent(self):
        """Missing 'status' → [] (kills the `or []` -> `and []` mutant)."""
        raw = {k: v for k, v in SAMPLE_RDAP.items() if k != "status"}
        assert RDAP().parse_domain(raw)["statuses"] == []


class TestRawRdapHttp:
    """Cover the raw ip/domain/autnum HTTP methods (24 no-cov mutants)."""

    def test_ip_calls_get_with_url_and_timeout(self):
        with patch("domain_profiler.rdap.requests.request") as mock_req:
            mock_req.return_value.json.return_value = {"ok": 1}
            out = RDAP().ip("8.8.8.8")
        args, kwargs = mock_req.call_args
        assert args[0] == "GET"
        assert kwargs["url"] == "https://www.rdap.net/ip/8.8.8.8"
        assert kwargs["timeout"] == RDAP.TIMEOUT
        assert out == {"ok": 1}

    def test_domain_calls_get_with_url_and_timeout(self):
        with patch("domain_profiler.rdap.requests.request") as mock_req:
            mock_req.return_value.json.return_value = {"ok": 2}
            out = RDAP().domain("example.com")
        args, kwargs = mock_req.call_args
        assert args[0] == "GET"
        assert kwargs["url"] == "https://www.rdap.net/domain/example.com"
        assert kwargs["timeout"] == RDAP.TIMEOUT
        assert out == {"ok": 2}

    def test_domain_uses_tld_specific_server_when_configured(self):
        with patch("domain_profiler.rdap.requests.request") as mock_req:
            mock_req.return_value.json.return_value = {"ok": 2}
            out = RDAP().domain("example.it")
        args, kwargs = mock_req.call_args
        assert args[0] == "GET"
        assert kwargs["url"] == "https://rdap.nic.it/domain/example.it"
        assert kwargs["timeout"] == RDAP.TIMEOUT
        assert out == {"ok": 2}

    def test_domain_falls_back_to_default_server_on_request_error(self):
        with patch("domain_profiler.rdap.requests.request") as mock_req:
            first_resp = requests.RequestException("network")
            second_resp = mock_req.return_value
            second_resp.json.return_value = {"ok": "fallback"}
            mock_req.side_effect = [first_resp, second_resp]
            out = RDAP().domain("example.it")

        assert mock_req.call_count == 2
        first_call = mock_req.call_args_list[0]
        second_call = mock_req.call_args_list[1]
        assert first_call.kwargs["url"] == "https://rdap.nic.it/domain/example.it"
        assert second_call.kwargs["url"] == "https://www.rdap.net/domain/example.it"
        assert out == {"ok": "fallback"}

    def test_domain_no_fallback_when_default_server_fails(self):
        with patch("domain_profiler.rdap.requests.request") as mock_req:
            mock_req.side_effect = requests.RequestException("boom")
            try:
                RDAP().domain("example.com")
                assert False, "Expected RequestException"
            except requests.RequestException:
                pass

        assert mock_req.call_count == 1
        assert mock_req.call_args.kwargs["url"] == "https://www.rdap.net/domain/example.com"

    def test_autnum_calls_get_with_url_and_timeout(self):
        with patch("domain_profiler.rdap.requests.request") as mock_req:
            mock_req.return_value.json.return_value = {"ok": 3}
            out = RDAP().autnum("15169")
        args, kwargs = mock_req.call_args
        assert args[0] == "GET"
        assert kwargs["url"] == "https://www.rdap.net/autnum/15169"
        assert kwargs["timeout"] == RDAP.TIMEOUT
        assert out == {"ok": 3}


class TestWhoisLookup:
    def test_whois_domain_delegates_to_python_whois(self):
        whois_raw = {
            "domain_name": "example.it",
            "registrar": "Registrar SpA",
            "status": ["ok"],
            "name_servers": ["ns1.example.it"],
        }
        with patch("domain_profiler.rdap.whois.whois", return_value=whois_raw) as mock_whois:
            result = RDAP().whois_domain("example.it")
        mock_whois.assert_called_once_with("example.it")
        assert result["domain"] == "example.it"
        assert result["source"] == "whois"

    def test_whois_report_returns_error_shape_on_lookup_failure(self):
        with patch("domain_profiler.rdap.whois.whois", side_effect=Exception("timeout")):
            result = RDAP().whois_report("example.it")
        assert result["domain"] == "example.it"
        assert result["source"] == "whois"
        assert result["error"].startswith("WHOIS lookup failed")
        assert result["statuses"] == []
        assert result["nameservers"] == []


class TestParseDomainErrorGuard:
    """Exercise the not-a-domain guard branch (kills its condition/get-key mutants)."""

    def test_error_object_with_errorcode(self):
        # No ldhName and not a domain object → error uses errorCode value.
        r = RDAP().parse_domain({"objectClassName": "error", "errorCode": 404})
        assert r["error"] == 404
        assert r["domain"] is None

    def test_error_object_without_errorcode_uses_message(self):
        # errorCode absent → falls back to the "Not an RDAP domain object" string.
        r = RDAP().parse_domain({"objectClassName": "error"})
        assert r["error"] == "Not an RDAP domain object"

    def test_ldhname_present_is_not_error_even_if_class_missing(self):
        # ldhName present → treated as a domain object (guard requires BOTH
        # non-domain class AND missing ldhName). Kills the and->or mutant.
        r = RDAP().parse_domain({"ldhName": "x.com", "events": [], "entities": []})
        assert r["error"] is None
        assert r["domain"] == "x.com"


class TestVcardField:
    """Directly exercise _vcard_field edge cases (kills its mutants)."""

    def test_missing_vcard_returns_none(self):
        assert RDAP._vcard_field({}, "fn") is None

    def test_short_vcard_returns_none(self):
        assert RDAP._vcard_field({"vcardArray": ["vcard"]}, "fn") is None

    def test_list_value_joined_with_space(self):
        entity = {"vcardArray": ["vcard", [["adr", {}, "text", ["123 St", "City"]]]]}
        assert RDAP._vcard_field(entity, "adr") == "123 St City"

    def test_scalar_value_stringified(self):
        entity = {"vcardArray": ["vcard", [["fn", {}, "text", "Acme Inc."]]]}
        assert RDAP._vcard_field(entity, "fn") == "Acme Inc."

    def test_field_not_found_returns_none(self):
        entity = {"vcardArray": ["vcard", [["fn", {}, "text", "Acme"]]]}
        assert RDAP._vcard_field(entity, "org") is None
