"""Wildcard DNS detection and dangling-CNAME subdomain-takeover checks.

Wildcard detection must run first: a ``*.example.com`` wildcard makes every name
"resolve", which both defeats subdomain enumeration and invalidates any
NXDOMAIN-based takeover signal — so the wildcard baseline has to be established
and subtracted before takeover checks are trustworthy.

Subdomain takeover: a CNAME (or NS delegation) that points at a cloud/SaaS
resource which is no longer provisioned lets an attacker claim that resource and
serve content from your trusted subdomain. Detection looks for a dangling target
(NXDOMAIN on the CNAME target) or a target on a known takeover-prone provider.
"""

import uuid
from typing import Any, Dict, List, Optional

import dns.rdatatype
import dns.resolver

from domain_profiler.base import Base


# Suffixes of services with a documented history of subdomain-takeover risk.
# A live CNAME to one of these is worth flagging for monitoring even when
# currently claimed; a dangling one (target NXDOMAIN) is a strong finding.
TAKEOVER_PRONE_PROVIDERS: Dict[str, str] = {
    "s3.amazonaws.com": "AWS S3",
    "cloudfront.net": "AWS CloudFront",
    "elasticbeanstalk.com": "AWS Elastic Beanstalk",
    "azurewebsites.net": "Azure App Service",
    "cloudapp.net": "Azure Cloud Service",
    "cloudapp.azure.com": "Azure",
    "trafficmanager.net": "Azure Traffic Manager",
    "blob.core.windows.net": "Azure Blob Storage",
    "github.io": "GitHub Pages",
    "herokuapp.com": "Heroku",
    "herokudns.com": "Heroku",
    "ghost.io": "Ghost",
    "fastly.net": "Fastly",
    "pantheonsite.io": "Pantheon",
    "wpengine.com": "WP Engine",
    "zendesk.com": "Zendesk",
    "helpscoutdocs.com": "Help Scout",
    "readthedocs.io": "Read the Docs",
    "surge.sh": "Surge.sh",
    "bitbucket.io": "Bitbucket",
    "netlify.app": "Netlify",
    "netlify.com": "Netlify",
    "shopify.com": "Shopify",
    "myshopify.com": "Shopify",
    "statuspage.io": "Statuspage",
    "unbouncepages.com": "Unbounce",
    "wixdns.net": "Wix",
    "fastly-edge.com": "Fastly",
}


class Takeover(Base):
    """Detect wildcard DNS and dangling-CNAME takeover risk."""

    QUERY_TIMEOUT: float = 5.0

    def _resolve(self, name: str, rdtype: Any) -> Optional[List[str]]:
        """Resolve name/rdtype. Returns values, [] for NoAnswer, None for NXDOMAIN/error."""
        try:
            answers = dns.resolver.resolve(name, rdtype, lifetime=self.QUERY_TIMEOUT)
            return [r.to_text() for r in answers]
        except dns.resolver.NoAnswer:
            return []
        except dns.resolver.NXDOMAIN:
            return None
        except Exception:
            return None

    def detect_wildcard(self, domain: str) -> Dict[str, Any]:
        """Detect a wildcard record by querying random, nonexistent labels.

        Two independent random labels are queried; if both resolve to the same
        address set, the zone synthesizes answers from a wildcard.

        Returns:
            ``{"wildcard": bool, "addresses": [...]}`` — addresses is the
            synthesized baseline to subtract from takeover/enumeration results.
        """
        probe_sets: List[set] = []
        for _ in range(2):
            label = f"{uuid.uuid4().hex}.{domain}"
            answers = self._resolve(label, dns.rdatatype.A)
            probe_sets.append(set(answers or []))

        # A wildcard yields the same synthesized answer for unrelated random
        # names; NXDOMAIN (None → empty set) on both means no wildcard.
        wildcard = bool(probe_sets[0]) and probe_sets[0] == probe_sets[1]
        return {
            "wildcard": wildcard,
            "addresses": sorted(probe_sets[0]) if wildcard else [],
        }

    @staticmethod
    def _match_provider(target: str) -> Optional[str]:
        target = target.lower().rstrip(".")
        for suffix, name in TAKEOVER_PRONE_PROVIDERS.items():
            if target == suffix or target.endswith("." + suffix):
                return name
        return None

    def check_subdomain(self, subdomain: str) -> Dict[str, Any]:
        """Check a single subdomain for dangling-CNAME takeover risk.

        Returns a dict with the CNAME target, matched provider (if any), whether
        the target is dangling (NXDOMAIN), and a risk verdict.
        """
        result: Dict[str, Any] = {
            "subdomain": subdomain,
            "cname": None,
            "provider": None,
            "dangling": False,
            "risk": "none",
            "notes": [],
        }

        cnames = self._resolve(subdomain, dns.rdatatype.CNAME)
        if not cnames:
            return result

        target = cnames[0].rstrip(".")
        result["cname"] = target
        provider = self._match_provider(target)
        result["provider"] = provider

        # Does the CNAME target itself resolve?
        target_a = self._resolve(target, dns.rdatatype.A)
        if target_a is None:
            # NXDOMAIN on the target while the CNAME still points at it: the
            # classic dangling-record takeover candidate.
            result["dangling"] = True
            if provider:
                result["risk"] = "high"
                result["notes"].append(
                    f"Dangling CNAME to unprovisioned {provider} resource — takeover candidate"
                )
            else:
                result["risk"] = "medium"
                result["notes"].append(
                    "CNAME target does not resolve (NXDOMAIN) — possible dangling record"
                )
        elif provider:
            result["risk"] = "low"
            result["notes"].append(
                f"CNAME to takeover-prone provider ({provider}) — monitor if deprovisioned"
            )

        return result

    def report(self, domain: str, subdomains: Optional[List[str]] = None) -> Dict[str, Any]:
        """Assemble a takeover report: wildcard baseline + per-subdomain checks.

        Args:
            domain: The apex domain (for wildcard detection).
            subdomains: Optional list of subdomains (FQDNs) to check for
                dangling CNAMEs. The apex itself is always checked.

        Returns:
            ``{"domain", "wildcard": {...}, "subdomains": [...]}``.
        """
        targets = list(subdomains or [])
        if domain not in targets:
            targets.insert(0, domain)

        return {
            "domain": domain,
            "wildcard": self.detect_wildcard(domain),
            "subdomains": [self.check_subdomain(sub) for sub in targets],
        }
