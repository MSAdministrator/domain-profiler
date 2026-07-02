"""DNSSEC validation.

Fetching a ``DNSKEY`` record only proves a zone *published* keys; it says
nothing about whether the chain of trust actually validates. This module goes
further:

* reads the **AD (Authenticated Data)** flag from a validating resolver — the
  cheap signal that *some* validating resolver verified the chain;
* fetches the zone's ``DNSKEY`` RRset with its ``RRSIG`` and cryptographically
  verifies the self-signature (proves the keys sign themselves);
* fetches the ``DS`` record from the **parent** zone and confirms it hashes to
  the zone's key-signing key (proves the delegation anchors upward).

The result distinguishes three security-relevant states:

* ``secure``   — signed and the chain validates;
* ``bogus``    — signed but signatures/DS fail to verify (misconfiguration or
  tampering — higher severity than merely unsigned);
* ``insecure`` — no DNSSEC (common, but responses are spoofable).
"""

from typing import Any, Dict, List, Optional

import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver

from domain_profiler.base import Base


# DNSSEC algorithm numbers considered cryptographically weak / deprecated.
# RSASHA1 (5), RSASHA1-NSEC3-SHA1 (7), and DSA (3, 6) should be flagged.
WEAK_DNSSEC_ALGORITHMS: Dict[int, str] = {
    1: "RSAMD5",
    3: "DSA",
    5: "RSASHA1",
    6: "DSA-NSEC3-SHA1",
    7: "RSASHA1-NSEC3-SHA1",
}


class DNSSEC(Base):
    """Validate the DNSSEC chain of trust for a zone."""

    QUERY_TIMEOUT: float = 5.0

    def _resolver_ad_flag(self, domain: str) -> Optional[bool]:
        """Ask a validating resolver whether it authenticated the answer.

        Returns True/False for the AD flag, or None if the query failed.
        """
        try:
            request = dns.message.make_query(
                domain, dns.rdatatype.A, want_dnssec=True
            )
            request.flags |= dns.flags.AD
            response = dns.query.udp(
                request, self._resolver_address(), timeout=self.QUERY_TIMEOUT
            )
            return bool(response.flags & dns.flags.AD)
        except Exception:
            return None

    @staticmethod
    def _resolver_address() -> str:
        """Return a validating resolver address (system resolver, else 1.1.1.1)."""
        try:
            nameservers = dns.resolver.get_default_resolver().nameservers
            if nameservers:
                return str(nameservers[0])
        except Exception:
            pass
        return "1.1.1.1"

    def _fetch_with_rrsig(self, name: dns.name.Name, rdtype: Any) -> Any:
        """Fetch an RRset plus its RRSIG for our own validation.

        The Checking Disabled (CD) flag is set so a validating resolver still
        returns records even when they are bogus — we want to verify them
        ourselves rather than have the resolver hide them behind a SERVFAIL.

        Returns the dns.message response, or None on failure.
        """
        try:
            request = dns.message.make_query(name, rdtype, want_dnssec=True)
            request.flags |= dns.flags.CD
            response = dns.query.udp(
                request, self._resolver_address(), timeout=self.QUERY_TIMEOUT
            )
            return response
        except Exception:
            return None

    def _is_bogus_servfail(self, name: dns.name.Name) -> bool:
        """Return True if a validating resolver rejects the zone as bogus.

        A validating resolver returns SERVFAIL for a bogus zone but NOERROR for
        an unsigned one, so a SERVFAIL here (with CD *unset*) distinguishes
        "signatures fail to validate" from "simply not signed".
        """
        try:
            request = dns.message.make_query(name, dns.rdatatype.DNSKEY, want_dnssec=True)
            response = dns.query.udp(
                request, self._resolver_address(), timeout=self.QUERY_TIMEOUT
            )
            return response.rcode() == dns.rcode.SERVFAIL
        except Exception:
            return False

    @staticmethod
    def _split_rrset_rrsig(response: Any, name: dns.name.Name, rdtype: Any):
        """Pull the (rrset, rrsigset) pair for rdtype out of a response answer."""
        rrset = None
        rrsig = None
        for answer in response.answer:
            if answer.rdtype == rdtype and answer.name == name:
                rrset = answer
            elif (
                answer.rdtype == dns.rdatatype.RRSIG
                and answer.covers == rdtype
                and answer.name == name
            ):
                rrsig = answer
        return rrset, rrsig

    def _collect_algorithms(self, dnskey_rrset: Any) -> List[int]:
        algorithms: List[int] = []
        for key in dnskey_rrset:
            algorithms.append(int(key.algorithm))
        return sorted(set(algorithms))

    def validate(self, domain: str) -> Dict[str, Any]:
        """Validate the DNSSEC chain of trust for a domain.

        Args:
            domain: The domain to validate.

        Returns:
            A dict describing the DNSSEC posture:
              ``status``: "secure" | "bogus" | "insecure" | "error"
              ``signed``: whether a DNSKEY RRset was found
              ``dnskey_validated``: DNSKEY self-signature verified
              ``ds_validated``: parent DS matches the zone KSK
              ``ad_flag``: validating-resolver Authenticated Data flag
              ``algorithms``: list of DNSSEC algorithm numbers in use
              ``weak_algorithms``: subset flagged as deprecated/weak
              ``errors``: human-readable notes on any failures
        """
        name = dns.name.from_text(domain)
        result: Dict[str, Any] = {
            "domain": domain,
            "status": "insecure",
            "signed": False,
            "dnskey_validated": False,
            "ds_validated": False,
            "ad_flag": self._resolver_ad_flag(domain),
            "algorithms": [],
            "weak_algorithms": [],
            "errors": [],
        }

        # 1. Fetch the zone's DNSKEY RRset + its RRSIG.
        dnskey_response = self._fetch_with_rrsig(name, dns.rdatatype.DNSKEY)
        if dnskey_response is None:
            result["status"] = "error"
            result["errors"].append("DNSKEY query failed")
            return result

        dnskey_rrset, dnskey_rrsig = self._split_rrset_rrsig(
            dnskey_response, name, dns.rdatatype.DNSKEY
        )
        if not dnskey_rrset:
            # No keys returned. Distinguish "unsigned" from "bogus": a validating
            # resolver SERVFAILs a bogus zone but answers NOERROR for an unsigned
            # one. SERVFAIL here means the chain fails to validate.
            if self._is_bogus_servfail(name):
                result["status"] = "bogus"
                result["errors"].append(
                    "Validating resolver returns SERVFAIL (bogus DNSSEC chain)"
                )
            return result

        result["signed"] = True
        result["algorithms"] = self._collect_algorithms(dnskey_rrset)
        result["weak_algorithms"] = [
            WEAK_DNSSEC_ALGORITHMS[a]
            for a in result["algorithms"]
            if a in WEAK_DNSSEC_ALGORITHMS
        ]

        # 2. Verify the DNSKEY RRset self-signature (keys sign themselves).
        if dnskey_rrsig is None:
            result["status"] = "bogus"
            result["errors"].append("DNSKEY present but no RRSIG found")
            return result
        try:
            dns.dnssec.validate(
                dnskey_rrset, dnskey_rrsig, {name: dnskey_rrset}
            )
            result["dnskey_validated"] = True
        except Exception as exc:  # dns.dnssec.ValidationFailure and friends
            result["status"] = "bogus"
            result["errors"].append(f"DNSKEY signature invalid: {exc}")
            return result

        # 3. Confirm the parent DS matches one of the zone's keys.
        ds_ok = self._validate_ds(name, dnskey_rrset, result)
        result["ds_validated"] = ds_ok

        if result["dnskey_validated"] and ds_ok:
            result["status"] = "secure"
        elif not ds_ok:
            # Self-signed keys with no matching parent DS = an island of trust;
            # treat as bogus since the chain does not anchor upward.
            result["status"] = "bogus"

        return result

    def _validate_ds(
        self, name: dns.name.Name, dnskey_rrset: Any, result: Dict[str, Any]
    ) -> bool:
        """Fetch the parent DS and confirm it hashes to a zone key."""
        try:
            ds_answer = dns.resolver.resolve(
                name, dns.rdatatype.DS, lifetime=self.QUERY_TIMEOUT
            )
        except dns.resolver.NoAnswer:
            result["errors"].append("No DS record at parent (delegation unsigned)")
            return False
        except Exception as exc:
            result["errors"].append(f"DS query failed: {exc}")
            return False

        published_ds = set()
        for ds in ds_answer:
            published_ds.add(ds.to_text())

        # Recompute the DS from each key and see if any matches what the parent
        # published. A match proves the delegation anchors to this zone's key.
        for key in dnskey_rrset:
            for digest in ("SHA256", "SHA384"):
                try:
                    candidate = dns.dnssec.make_ds(name, key, digest)
                except Exception:
                    continue
                if candidate.to_text() in published_ds:
                    return True
        result["errors"].append("Parent DS does not match any zone DNSKEY")
        return False
