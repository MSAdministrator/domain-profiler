"""Main profiler functionality for domain analysis."""

from typing import Any, Dict
from urllib.parse import urlparse

from domain_profiler.base import Base
from domain_profiler.dns import DNSCheck
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
            # No scheme/netloc: treat the input as a bare domain and drop any
            # stray userinfo, path, or ":port" the user may have appended.
            host = domain.split('/')[0].split('@')[-1].split(':')[0]
        return host.strip().lower().rstrip('.')

    def run(self, domain: str, live: bool = False) -> Dict[str, Any]:
        """Run domain analysis with optional live website analysis.

        Args:
            domain: The domain or URL to analyze
            live: Whether to include live website analysis

        Returns:
            Dictionary containing analysis results
        """
        value = self._normalize_domain(domain)
        response = DNSCheck().get_report(domain=value)
        if live:
            response.update(
                Url(url=f"https://{value}").to_json()
            )
        return response

    def rdap(self) -> RDAP:
        return RDAP()
