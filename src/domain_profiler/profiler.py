"""Main profiler functionality for domain analysis."""

from typing import Any, Dict, Optional
from urllib.parse import urlparse

from domain_profiler.base import Base
from domain_profiler.caa import CAA
from domain_profiler.dns import DNSCheck
from domain_profiler.dnssec import DNSSEC
from domain_profiler.email_auth import EmailAuth
from domain_profiler.site import Url
from domain_profiler.rdap import RDAP
from domain_profiler.takeover import Takeover
from domain_profiler.tls import TLSInspector
from domain_profiler.typosquat import Typosquat


class Profiler(Base):
    """Main profiler class for analyzing domains."""

    @staticmethod
    def _normalize_domain(domain: str) -> str:
        """Reduce a URL or domain to a bare, resolvable hostname.

        Strips any scheme, port, userinfo, and path, then lowercases and
        removes a trailing dot so the result can be passed straight to the
        resolver / socket lookups.

        Args:
            domain: The domain or URL supplied by the caller.

        Returns:
            A bare hostname (may be empty if the input has none).
        """
        host = urlparse(domain).hostname
        if not host:
            # No scheme/netloc: re-parse with a leading "//" so urllib treats the
            # whole input as a netloc. This strips userinfo/port/path and handles
            # IPv6 literals (e.g. "[2001:db8::1]:443") correctly, which manual
            # ":"-splitting would mangle.
            host = urlparse(f"//{domain}").hostname or ""
        return host.strip().lower().rstrip('.')

    def run(
        self,
        domain: str,
        live: bool = False,
        email: bool = False,
        security: bool = False,
        dkim_selector: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Run domain analysis with optional website, email, and security analysis.

        Args:
            domain: The domain or URL to analyze
            live: Whether to include live website analysis
            email: Whether to include email-authentication analysis
                (SPF/DKIM/DMARC/BIMI/MX)
            security: Whether to include DNS-layer security analysis
                (DNSSEC validation, CAA policy, RDAP registration data)
            dkim_selector: Optional extra DKIM selector to probe first

        Returns:
            Dictionary containing analysis results
        """
        value = self._normalize_domain(domain)
        response = DNSCheck().get_report(domain=value)
        if live:
            response.update(
                Url(url=f"https://{value}").to_json()
            )
        if email:
            response["email_auth"] = EmailAuth().get_report(
                domain=value, dkim_selector=dkim_selector
            )
        if security:
            response["security"] = self._security_report(value)
        return response

    @staticmethod
    def _security_report(value: str) -> Dict[str, Any]:
        """Assemble the DNS-layer + TLS security section for a normalized host."""
        return {
            "dnssec": DNSSEC().validate(value),
            "caa": CAA().analyze(value),
            "rdap": RDAP().report(value),
            "tls": TLSInspector().inspect(value),
            "takeover": Takeover().report(value),
        }

    def security(self, domain: str) -> Dict[str, Any]:
        """Run only security analysis for a domain.

        Args:
            domain: The domain or URL to analyze

        Returns:
            Dict with dnssec, caa, rdap, tls, and takeover sections.
        """
        return self._security_report(self._normalize_domain(domain))

    def tls(self, domain: str, port: int = 443) -> Dict[str, Any]:
        """Inspect the TLS certificate presented by a host.

        Args:
            domain: The domain or URL to connect to.
            port: TLS port (default 443).

        Returns:
            Certificate details and derived security flags.
        """
        return TLSInspector().inspect(self._normalize_domain(domain), port=port)

    def takeover(self, domain: str) -> Dict[str, Any]:
        """Check a domain for wildcard DNS and dangling-CNAME takeover risk.

        Args:
            domain: The domain or URL to analyze.

        Returns:
            Dict with wildcard baseline and per-subdomain takeover checks.
        """
        return Takeover().report(self._normalize_domain(domain))

    def typosquat(self, domain: str, brand: str) -> Dict[str, Any]:
        """Score how likely a domain is a typosquat/look-alike of a brand.

        Args:
            domain: The candidate domain to evaluate.
            brand: The legitimate brand domain to compare against (required).

        Returns:
            Similarity scores, IDN/homoglyph flags, and a suspicious verdict.
        """
        return Typosquat().analyze(
            self._normalize_domain(domain), self._normalize_domain(brand)
        )

    def email(self, domain: str, dkim_selector: Optional[str] = None) -> Dict[str, Any]:
        """Resolve only a domain's email-authentication posture.

        Args:
            domain: The domain or URL to analyze
            dkim_selector: Optional extra DKIM selector to probe first

        Returns:
            Dict with spf/spf_tree/spf_flattened, dkim, dmarc, bimi, mx_records.
        """
        return EmailAuth().get_report(
            domain=self._normalize_domain(domain), dkim_selector=dkim_selector
        )

    def rdap(self) -> RDAP:
        return RDAP()
