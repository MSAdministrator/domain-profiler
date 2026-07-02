"""Main profiler functionality for domain analysis."""

from typing import Any, Dict, Optional
from urllib.parse import urlparse

from domain_profiler.base import Base
from domain_profiler.dns import DNSCheck
from domain_profiler.email_auth import EmailAuth
from domain_profiler.site import Url
from domain_profiler.rdap import RDAP


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
        dkim_selector: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Run domain analysis with optional live website and email analysis.

        Args:
            domain: The domain or URL to analyze
            live: Whether to include live website analysis
            email: Whether to include email-authentication analysis
                (SPF/DKIM/DMARC/BIMI/MX)
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
        return response

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
