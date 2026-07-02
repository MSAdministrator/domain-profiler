"""CAA (Certification Authority Authorization) analysis.

A CAA record (RFC 8659) is a domain owner's allowlist of which CAs may issue
certificates for the domain. Absent CAA, *any* CA may issue — not a
vulnerability per se, but for a high-value brand it widens the mis-issuance /
adversary-obtained-certificate surface, so a profiler should surface it.

CA issuance climbs the DNS tree: if there is no CAA at the FQDN, the CA walks
up label by label toward the registrable domain. This module mirrors that
tree-climb so the reported policy is the one a CA would actually apply.
"""

from typing import Any, Dict, List, Optional

import dns.name
import dns.rdatatype
import dns.resolver

from domain_profiler.base import Base


class CAA(Base):
    """Fetch and interpret a domain's CAA issuance policy."""

    QUERY_TIMEOUT: float = 5.0

    def _query_caa(self, name: str) -> Optional[List[Dict[str, Any]]]:
        """Query CAA at a single name. Returns records, [] for NoAnswer, None on error."""
        try:
            answers = dns.resolver.resolve(
                name, dns.rdatatype.CAA, lifetime=self.QUERY_TIMEOUT
            )
        except dns.resolver.NoAnswer:
            return []
        except dns.resolver.NXDOMAIN:
            return []
        except Exception:
            return None

        records: List[Dict[str, Any]] = []
        for rdata in answers:
            value = rdata.value
            if isinstance(value, (bytes, bytearray)):
                value = value.decode("utf-8", "replace")
            records.append(
                {
                    "flags": int(rdata.flags),
                    "tag": rdata.tag.decode("ascii", "replace")
                    if isinstance(rdata.tag, (bytes, bytearray))
                    else str(rdata.tag),
                    "value": value,
                    "critical": bool(int(rdata.flags) & 0x80),
                }
            )
        return records

    def analyze(self, domain: str) -> Dict[str, Any]:
        """Analyze the CAA issuance policy that applies to a domain.

        Walks up the DNS tree from the FQDN toward the apex (as a CA does),
        stopping at the first label that has a CAA RRset.

        Args:
            domain: The domain to analyze.

        Returns:
            A dict describing the effective policy:
              ``present``: whether any CAA record governs the domain
              ``policy_domain``: the label the CAA was found at (tree-climb result)
              ``records``: the raw CAA records at that label
              ``issue``: CAs allowed to issue non-wildcard certs
              ``issuewild``: CAs allowed to issue wildcard certs
              ``iodef``: violation-report endpoints
              ``allows_any_ca``: True when no CAA restricts issuance
              ``forbids_issuance``: True when policy explicitly forbids all issuance
              ``notes``: security-relevant observations
        """
        result: Dict[str, Any] = {
            "domain": domain,
            "present": False,
            "policy_domain": None,
            "records": [],
            "issue": [],
            "issuewild": [],
            "iodef": [],
            "allows_any_ca": True,
            "forbids_issuance": False,
            "notes": [],
        }

        name = dns.name.from_text(domain)
        # Climb from the FQDN up toward (but not past) the root, mirroring how a
        # CA searches for the applicable policy.
        labels = name.labels
        for i in range(len(labels) - 1):
            candidate = dns.name.Name(labels[i:])
            candidate_text = candidate.to_text(omit_final_dot=True)
            if not candidate_text:
                continue
            records = self._query_caa(candidate_text)
            if records is None:
                result["notes"].append(f"CAA query error at {candidate_text}")
                continue
            if records:
                result["present"] = True
                result["policy_domain"] = candidate_text
                result["records"] = records
                self._interpret(records, result)
                return result

        result["notes"].append(
            "No CAA record found — any CA may issue certificates for this domain"
        )
        return result

    def _interpret(self, records: List[Dict[str, Any]], result: Dict[str, Any]) -> None:
        """Populate issue/issuewild/iodef and derived flags from raw records."""
        for record in records:
            tag = record["tag"].lower()
            value = record["value"].strip()
            if tag == "issue":
                result["issue"].append(value)
            elif tag == "issuewild":
                result["issuewild"].append(value)
            elif tag == "iodef":
                result["iodef"].append(value)
            elif record["critical"]:
                # An unknown tag marked critical blocks issuance entirely (RFC 8659).
                result["notes"].append(
                    f"Unknown critical CAA tag '{tag}' — CAs must refuse issuance"
                )

        result["allows_any_ca"] = not (result["issue"] or result["issuewild"])

        # An empty issue value (`issue ";"`) means no CA may issue.
        issue_values = result["issue"] + result["issuewild"]
        non_empty = [v for v in issue_values if v and not v.startswith(";")]
        if issue_values and not non_empty:
            result["forbids_issuance"] = True
            result["notes"].append("CAA policy forbids all certificate issuance")

        if not result["iodef"]:
            result["notes"].append(
                "No iodef contact — CA cannot report mis-issuance attempts"
            )
