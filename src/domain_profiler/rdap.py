"""RDAP (Registration Data Access Protocol) lookups and parsing.

RDAP is the structured-JSON successor to WHOIS. The raw ``ip``/``domain``/
``autnum`` methods return the registry response verbatim; :meth:`RDAP.parse_domain`
and :meth:`RDAP.report` extract the security-relevant fields — registration and
expiry dates, EPP status codes, registrar, nameservers, and DNSSEC delegation —
into a stable shape suitable for a domain profile.
"""

import socket
from datetime import date
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests
import whois

from domain_profiler.base import Base


class RDAP(Base):

    BASE_URL: str = "https://www.rdap.net"
    TIMEOUT: float = 15.0
    
    # TLD-specific RDAP servers
    TLD_SERVERS: Dict[str, str] = {
        "it": "https://rdap.nic.it",
        "de": "https://rdap.denic.de",
        "fr": "https://rdap.afnic.fr",
        "uk": "https://rdap.nominet.uk",
        "br": "https://rdap.registro.br",
        "ru": "https://rdap.tcinet.ru",
        "cn": "https://rdap.cnnic.cn",
        "au": "https://rdap.auda.org.au",
        "ca": "https://rdap.cira.ca",
        "ch": "https://rdap.switch.ch",
        "at": "https://rdap.nic.at",
        "nl": "https://rdap.sidn.nl",
        "be": "https://rdap.dns.be",
        "se": "https://rdap.iis.se",
        "no": "https://rdap.norid.no",
        "fi": "https://rdap.ficora.fi",
        "pl": "https://rdap.dns.pl",
        "es": "https://rdap.es",
        "mx": "https://rdap.mx",
        "in": "https://rdap.registry.in",
        "jp": "https://rdap.jprs.jp",
        "sg": "https://rdap.sgnic.sg",
    }

    def _get_rdap_url(self, domain: str) -> str:
        """Get the appropriate RDAP base URL for a domain based on TLD."""
        # Extract TLD
        parts = domain.lower().split(".")
        if len(parts) < 2:
            return self.BASE_URL
        
        tld = parts[-1]
        return self.TLD_SERVERS.get(tld, self.BASE_URL)

    @staticmethod
    def _is_host_resolvable(url: str) -> bool:
        """Return True if URL host resolves in local DNS."""
        host = urlparse(url).hostname
        if not host:
            return False
        try:
            socket.getaddrinfo(host, None)
            return True
        except OSError:
            return False

    def ip(self, ipaddress: str) -> dict:
        resp = requests.request(
            "GET",
            url=f"{self.BASE_URL}/ip/{ipaddress}",
            timeout=self.TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()

    def domain(self, domain: str) -> dict:
        base_url = self._get_rdap_url(domain)
        if base_url != self.BASE_URL and not self._is_host_resolvable(base_url):
            base_url = self.BASE_URL
        try:
            resp = requests.request(
                "GET",
                url=f"{base_url}/domain/{domain}",
                timeout=self.TIMEOUT,
            )
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException:
            if base_url == self.BASE_URL:
                raise

            # Fallback to rdap.net when the registry-specific service is
            # unavailable or unreachable from this network.
            resp = requests.request(
                "GET",
                url=f"{self.BASE_URL}/domain/{domain}",
                timeout=self.TIMEOUT,
            )
            resp.raise_for_status()
            return resp.json()

    def autnum(self, autnum: str) -> dict:
        resp = requests.request(
            "GET",
            url=f"{self.BASE_URL}/autnum/{autnum}",
            timeout=self.TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()

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

    @staticmethod
    def _coerce_whois_date(value: Any) -> Optional[str]:
        """Normalize WHOIS date fields to an ISO string."""
        if isinstance(value, (list, tuple)):
            value = value[-1] if value else None
        if isinstance(value, date):
            return value.isoformat()
        return str(value) if value else None

    @staticmethod
    def _as_list(value: Any) -> List[str]:
        """Normalize scalar/list WHOIS fields to a string list."""
        if value is None:
            return []
        if isinstance(value, (list, tuple, set)):
            return [str(item) for item in value if item]
        return [str(value)]

    @classmethod
    def _as_nameserver_list(cls, value: Any) -> List[str]:
        """Normalize WHOIS nameserver fields, including newline-delimited values."""
        nameservers: List[str] = []
        for item in cls._as_list(value):
            parts = [part.strip() for part in item.splitlines() if part.strip()]
            if parts:
                nameservers.extend(parts)
            elif item.strip():
                nameservers.append(item.strip())
        return nameservers

    @staticmethod
    def _first_value(value: Any) -> Optional[str]:
        """Return the first non-empty scalar from a WHOIS field."""
        values = RDAP._as_list(value)
        return values[0] if values else None

    def parse_whois_domain(self, raw: Dict[str, Any], domain: str) -> Dict[str, Any]:
        """Extract a RDAP-like summary from python-whois data."""
        nameservers = sorted(set(self._as_nameserver_list(raw.get("name_servers"))))
        statuses = self._as_list(raw.get("status"))
        return {
            "domain": self._first_value(raw.get("domain_name")) or domain,
            "handle": None,
            "registrar": self._first_value(raw.get("registrar")),
            "registrar_iana_id": None,
            "registered": self._coerce_whois_date(raw.get("creation_date")),
            "expires": self._coerce_whois_date(raw.get("expiration_date")),
            "last_changed": self._coerce_whois_date(raw.get("updated_date")),
            "statuses": statuses,
            "nameservers": nameservers,
            "dnssec_delegated": None,
            "error": None,
            "source": "whois",
        }

    def whois_domain(self, domain: str) -> Dict[str, Any]:
        """Fetch WHOIS data and normalize it to the RDAP report shape."""
        return self.parse_whois_domain(whois.whois(domain), domain)

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
        except requests.HTTPError as exc:
            status_code = exc.response.status_code if exc.response is not None else None
            failed_url = exc.response.url if exc.response is not None else None
            if status_code == 404:
                detail = "RDAP record not found at provider"
                if failed_url:
                    detail = f"{detail}: {failed_url}"
                return {"domain": domain, "error": detail}
            return {
                "domain": domain,
                "error": f"RDAP HTTP error ({status_code}): {exc}",
            }
        except Exception as exc:
            return {"domain": domain, "error": f"RDAP lookup failed: {exc}"}
        try:
            return self.parse_domain(raw)
        except Exception as exc:
            return {"domain": domain, "error": f"RDAP parse failed: {exc}"}
