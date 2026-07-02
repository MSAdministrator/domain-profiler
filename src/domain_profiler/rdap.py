"""RDAP (Registration Data Access Protocol) lookups and parsing.

RDAP is the structured-JSON successor to WHOIS. The raw ``ip``/``domain``/
``autnum`` methods return the registry response verbatim; :meth:`RDAP.parse_domain`
and :meth:`RDAP.report` extract the security-relevant fields — registration and
expiry dates, EPP status codes, registrar, nameservers, and DNSSEC delegation —
into a stable shape suitable for a domain profile.
"""

from typing import Any, Dict, List, Optional

import requests

from domain_profiler.base import Base


class RDAP(Base):

    BASE_URL: str = "https://www.rdap.net"
    TIMEOUT: float = 15.0

    def ip(self, ipaddress: str) -> dict:
        return requests.request(
            "GET",
            url=f"{self.BASE_URL}/ip/{ipaddress}",
            timeout=self.TIMEOUT,
        ).json()

    def domain(self, domain: str) -> dict:
        return requests.request(
            "GET",
            url=f"{self.BASE_URL}/domain/{domain}",
            timeout=self.TIMEOUT,
        ).json()

    def autnum(self, autnum: str) -> dict:
        return requests.request(
            "GET",
            url=f"{self.BASE_URL}/autnum/{autnum}",
            timeout=self.TIMEOUT,
        ).json()

    # -- parsing ------------------------------------------------------------

    @staticmethod
    def _event_date(events: List[Dict[str, Any]], action: str) -> Optional[str]:
        """Return the eventDate for a given eventAction, or None."""
        for event in events or []:
            if event.get("eventAction") == action:
                return event.get("eventDate")
        return None

    @staticmethod
    def _vcard_field(entity: Dict[str, Any], field: str) -> Optional[str]:
        """Pull a named field (e.g. 'fn', 'org') out of an RDAP jCard/vCard."""
        vcard = entity.get("vcardArray")
        if not vcard or len(vcard) < 2:
            return None
        for item in vcard[1]:
            # Each item is [name, params, type, value].
            if len(item) >= 4 and item[0] == field:
                value = item[3]
                if isinstance(value, list):
                    return " ".join(str(v) for v in value)
                return str(value)
        return None

    @classmethod
    def _find_entity(cls, entities: List[Dict[str, Any]], role: str) -> Optional[Dict[str, Any]]:
        """Find the first entity holding a given role."""
        for entity in entities or []:
            if role in (entity.get("roles") or []):
                return entity
        return None

    def parse_domain(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Extract security-relevant fields from a raw RDAP domain response.

        Args:
            raw: The dict returned by :meth:`domain`.

        Returns:
            A structured summary with registrar, dates, statuses, nameservers,
            and DNSSEC delegation status. ``error`` is set if the response does
            not look like a domain object.
        """
        result: Dict[str, Any] = {
            "domain": raw.get("ldhName"),
            "handle": raw.get("handle"),
            "registrar": None,
            "registrar_iana_id": None,
            "registered": None,
            "expires": None,
            "last_changed": None,
            "statuses": raw.get("status") or [],
            "nameservers": [],
            "dnssec_delegated": None,
            "error": None,
        }

        if raw.get("objectClassName") != "domain" and not raw.get("ldhName"):
            result["error"] = raw.get("errorCode") or "Not an RDAP domain object"
            return result

        events = raw.get("events") or []
        result["registered"] = self._event_date(events, "registration")
        result["expires"] = self._event_date(events, "expiration")
        result["last_changed"] = self._event_date(events, "last changed")

        registrar = self._find_entity(raw.get("entities", []), "registrar")
        if registrar:
            result["registrar"] = (
                self._vcard_field(registrar, "fn")
                or self._vcard_field(registrar, "org")
            )
            for public_id in registrar.get("publicIds") or []:
                if public_id.get("type") == "IANA Registrar ID":
                    result["registrar_iana_id"] = public_id.get("identifier")

        result["nameservers"] = [
            ns.get("ldhName") for ns in raw.get("nameservers") or [] if ns.get("ldhName")
        ]

        secure_dns = raw.get("secureDNS")
        if isinstance(secure_dns, dict) and "delegationSigned" in secure_dns:
            result["dnssec_delegated"] = bool(secure_dns["delegationSigned"])

        return result

    def report(self, domain: str) -> Dict[str, Any]:
        """Fetch and parse RDAP for a domain into a structured summary.

        Network/parse failures degrade to an ``error`` field rather than raising.
        """
        try:
            raw = self.domain(domain)
        except Exception as exc:
            return {"domain": domain, "error": f"RDAP lookup failed: {exc}"}
        try:
            return self.parse_domain(raw)
        except Exception as exc:
            return {"domain": domain, "error": f"RDAP parse failed: {exc}"}
