"""Tests for RDAP parsing."""

from unittest.mock import patch

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
        assert "error" in result and "failed" in result["error"]

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
