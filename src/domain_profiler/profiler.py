"""Main profiler functionality for domain analysis."""

from typing import Any, Dict
from urllib.parse import urlparse

from domain_profiler.base import Base
from domain_profiler.dns import DNSCheck
from domain_profiler.site import Url
from domain_profiler.rdap import RDAP


class Profiler(Base):
    """Main profiler class for analyzing domains."""

    def run(self, domain: str, live: bool = False) -> Dict[str, Any]:
        """Run domain analysis with optional live website analysis.
        
        Args:
            domain: The domain or URL to analyze
            live: Whether to include live website analysis
            
        Returns:
            Dictionary containing analysis results
        """
        value = urlparse(domain).netloc
        if not value:
            value = domain    
        response = DNSCheck().get_report(domain=value)
        if live:
            response.update(
                Url(url=f"https://{value}").to_json()
            )
        return response

    def rdap(self) -> RDAP:
        return RDAP()
