"""Email-authentication resolution: SPF, DKIM, DMARC, BIMI, and MX.

Ports the resolution behaviour of the cloudflare ``web-apps/resolve`` app:

* SPF is parsed into structured mechanisms and then recursively resolved,
  following ``include:``/``redirect=`` while honouring the RFC 7208 §4.6.4
  10-lookup limit, a recursion-depth cap, and a loop guard, and flattening
  ``a``/``mx``/``ip4``/``ip6`` into an effective IP set.
* DMARC (``_dmarc.<domain>``) and BIMI (``default._bimi.<domain>``) TXT records
  are parsed into structured records.
* DKIM has no enumeration mechanism, so a list of common selectors is probed at
  ``<selector>._domainkey.<domain>``. A random probe selector detects a
  ``*._domainkey`` wildcard so echoed records can be dropped.
* MX hosts are parsed and mapped to well-known providers.

Parsers return ``None`` on non-match; network failures degrade to "no record"
rather than raising.
"""

import re
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple

from dns import resolver

from domain_profiler.base import Base


# --- SPF -------------------------------------------------------------------

SPF_QUALIFIERS = {"+", "-", "~", "?"}


def parse_spf_part(part: str) -> Dict[str, Optional[str]]:
    """Parse a single SPF mechanism/modifier token.

    The default qualifier is ``"+"`` when no ``+``/``-``/``~``/``?`` prefix is
    present, mirroring RFC 7208.
    """
    qualifier = "+"
    rest = part
    if rest and rest[0] in SPF_QUALIFIERS:
        qualifier = rest[0]
        rest = rest[1:]

    if rest == "all":
        return {"qualifier": qualifier, "type": "all", "value": None}
    if rest.startswith("redirect="):
        return {"qualifier": qualifier, "type": "redirect", "value": rest[len("redirect="):]}
    if rest.startswith("exp="):
        return {"qualifier": qualifier, "type": "exp", "value": rest[len("exp="):]}

    colon = rest.find(":")
    if colon > 0:
        return {"qualifier": qualifier, "type": rest[:colon], "value": rest[colon + 1:]}
    if rest in ("a", "mx", "ptr"):
        return {"qualifier": qualifier, "type": rest, "value": None}
    if rest.startswith("a/") or rest.startswith("mx/"):
        return {"qualifier": qualifier, "type": rest.split("/")[0], "value": rest}
    return {"qualifier": qualifier, "type": "unknown", "value": rest}


def parse_spf(txt: str) -> Optional[Dict[str, Any]]:
    """Parse an SPF TXT record into a structured record, or None if not SPF."""
    raw = txt.strip()
    if not raw.startswith("v=spf1"):
        return None

    mechanisms: List[Dict[str, Optional[str]]] = []
    includes: List[str] = []
    ip4s: List[str] = []
    ip6s: List[str] = []
    redirects: List[str] = []
    all_qualifier: Optional[str] = None

    for part in raw.split()[1:]:  # drop the leading v=spf1 token
        mechanism = parse_spf_part(part)
        mechanisms.append(mechanism)
        mtype = mechanism["type"]
        value = mechanism["value"]
        if mtype == "include" and value:
            includes.append(value)
        elif mtype == "ip4" and value:
            ip4s.append(value)
        elif mtype == "ip6" and value:
            ip6s.append(value)
        elif mtype == "redirect" and value:
            redirects.append(value)
        elif mtype == "all":
            all_qualifier = mechanism["qualifier"]

    return {
        "version": "spf1",
        "mechanisms": mechanisms,
        "all_qualifier": all_qualifier,
        "includes": includes,
        "ip4s": ip4s,
        "ip6s": ip6s,
        "redirects": redirects,
        "raw": raw,
    }


# --- DMARC / BIMI / DKIM tag parsing --------------------------------------

def _parse_tags(raw: str) -> Dict[str, str]:
    """Parse ``;``-separated ``key=value`` tags; keys lowercased and trimmed."""
    tags: Dict[str, str] = {}
    for segment in raw.split(";"):
        if "=" not in segment:
            continue
        key, _, value = segment.partition("=")
        tags[key.strip().lower()] = value.strip()
    return tags


def _dmarc_policy(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    lowered = value.strip().lower()
    if lowered in ("quarantine", "reject"):
        return lowered
    return "none"


def _parse_mailto_list(value: Optional[str]) -> List[str]:
    if not value:
        return []
    result: List[str] = []
    for item in value.split(","):
        item = item.strip()
        if item.lower().startswith("mailto:"):
            item = item[len("mailto:"):]
        if item:
            result.append(item)
    return result


def parse_dmarc(txt: str) -> Optional[Dict[str, Any]]:
    """Parse a DMARC TXT record, or None if it is not a DMARC record."""
    raw = txt.strip()
    if not raw.startswith("v=DMARC1"):
        return None
    tags = _parse_tags(raw)

    pct = 100
    if "pct" in tags:
        try:
            pct = min(100, max(0, int(tags["pct"])))
        except ValueError:
            pct = 100

    return {
        "version": "DMARC1",
        "policy": _dmarc_policy(tags.get("p")) or "none",
        "subdomain_policy": _dmarc_policy(tags["sp"]) if "sp" in tags else None,
        "rua": _parse_mailto_list(tags.get("rua")),
        "ruf": _parse_mailto_list(tags.get("ruf")),
        "pct": pct,
        "adkim": "s" if tags.get("adkim") == "s" else "r",
        "aspf": "s" if tags.get("aspf") == "s" else "r",
        "raw": raw,
    }


def parse_bimi(txt: str, selector: str = "default") -> Optional[Dict[str, Any]]:
    """Parse a BIMI TXT record, or None if it is not a BIMI record."""
    raw = txt.strip()
    if not re.match(r"^v\s*=\s*BIMI1\b", raw, re.IGNORECASE):
        return None
    tags = _parse_tags(raw)
    logo_url = tags.get("l", "")
    authority = tags.get("a", "").strip()
    return {
        "selector": selector,
        "version": "BIMI1",
        "logo_url": logo_url,
        "authority_url": authority or None,
        "declined": logo_url == "",
        "raw": raw,
    }


def parse_dkim(raw: str, selector: str) -> Optional[Dict[str, Any]]:
    """Parse a DKIM key record; accepted if it has ``v=DKIM1`` or a ``p=`` tag."""
    has_version = re.search(r"(^|;)\s*v\s*=\s*DKIM1", raw, re.IGNORECASE)
    has_key = re.search(r"(^|;)\s*p\s*=", raw, re.IGNORECASE)
    if not has_version and not has_key:
        return None
    tags = _parse_tags(raw)
    return {
        "selector": selector,
        "version": tags.get("v", "DKIM1"),
        "key_type": tags.get("k", "rsa"),
        "public_key": tags.get("p", ""),
        "service_type": tags.get("s"),
        "flags": tags.get("t"),
        "raw": raw,
    }


def reconcile_dkim_wildcard(
    found: List[Dict[str, Any]], wildcard: Optional[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Drop selector records that merely echo a ``*._domainkey`` wildcard.

    A wildcard answers every unconfigured selector with an identical record, so
    any real-selector result whose ``raw`` equals the wildcard's is noise.
    """
    if wildcard is None:
        return found
    return [record for record in found if record["raw"] != wildcard["raw"]]


# --- MX --------------------------------------------------------------------

MX_PROVIDERS: List[Tuple["re.Pattern[str]", str]] = [
    (re.compile(r"\.google\.com$"), "Google Workspace"),
    (re.compile(r"\.googlemail\.com$"), "Google Workspace"),
    (re.compile(r"\.mail\.protection\.outlook\.com$"), "Microsoft 365"),
    (re.compile(r"\.pphosted\.com$"), "Proofpoint"),
    (re.compile(r"\.mimecast\.com$"), "Mimecast"),
    (re.compile(r"\.barracudanetworks\.com$"), "Barracuda"),
    (re.compile(r"\.messagelabs\.com$"), "Broadcom (MessageLabs)"),
    (re.compile(r"\.iphmx\.com$"), "Cisco IronPort"),
    (re.compile(r"\.secureserver\.net$"), "GoDaddy"),
    (re.compile(r"\.zoho\.com$"), "Zoho Mail"),
    (re.compile(r"\.emailsrvr\.com$"), "Rackspace"),
    (re.compile(r"\.fireeyecloud\.com$"), "Trellix (FireEye)"),
    (re.compile(r"\.ess\.barracuda\.com$"), "Barracuda ESS"),
    (re.compile(r"\.abnormalcloud\.com$"), "Abnormal Security"),
    (re.compile(r"\.mail\.icloud\.com$"), "iCloud"),
    (re.compile(r"\.mx\.cloudflare\.net$"), "Cloudflare Email Routing"),
    (re.compile(r"^inbound-smtp\.[a-z0-9-]+\.amazonaws\.com$"), "Amazon SES"),
]


def identify_mx_provider(hostname: str) -> Optional[str]:
    """Return the well-known mail provider for an MX host, or None."""
    for pattern, name in MX_PROVIDERS:
        if pattern.search(hostname):
            return name
    return None


def parse_mx_record(data: str) -> Dict[str, Any]:
    """Parse an MX record ("<priority> <host>") into a structured record."""
    parts = data.strip().split()
    try:
        priority = int(parts[0]) if parts else 0
    except ValueError:
        priority = 0
    hostname = (parts[1] if len(parts) > 1 else "").rstrip(".").lower()
    return {"priority": priority, "hostname": hostname, "provider": identify_mx_provider(hostname)}


# --- shared helpers --------------------------------------------------------

_LABEL_RE = re.compile(r"^[a-zA-Z0-9_]([a-zA-Z0-9_-]*[a-zA-Z0-9_])?$")


def is_queryable_domain(domain: str) -> bool:
    """Loosely validate a domain before issuing a DNS query (RFC label rules)."""
    if not domain:
        return False
    stripped = domain.rstrip(".")
    if len(stripped) > 253:
        return False
    labels = stripped.split(".")
    if len(labels) < 2:
        return False
    return all(1 <= len(label) <= 63 and _LABEL_RE.match(label) for label in labels)


def _rdata_to_string(rdata: Any, record_type: str) -> str:
    """Render a dnspython rdata to text.

    For TXT records, concatenate the character-strings directly (RFC 7208 §3.3)
    using ``.strings`` when available so quoting never leaks into the value.
    """
    if record_type == "TXT":
        strings = getattr(rdata, "strings", None)
        if strings is not None:
            return "".join(
                s.decode("utf-8", "replace") if isinstance(s, (bytes, bytearray)) else str(s)
                for s in strings
            )
    return rdata.to_text()


# --- resolution constants --------------------------------------------------

SPF_LOOKUP_LIMIT = 10  # RFC 7208 §4.6.4 DNS-querying-mechanism cap
MAX_DEPTH = 10  # include/redirect recursion backstop
MAX_FLATTEN_HOSTS = 10  # A/AAAA records expanded per mechanism


class EmailAuth(Base):
    """Resolve a domain's email-authentication posture."""

    QUERY_TIMEOUT: float = 5.0
    MAX_DKIM_SELECTORS: int = 30

    # Common DKIM selectors probed when no explicit selector is supplied. DKIM
    # has no enumeration mechanism, so coverage is a function of this list.
    COMMON_DKIM_SELECTORS: List[str] = [
        "google", "selector1", "selector2", "default", "k1", "k2", "k3",
        "dkim", "s1", "s2", "mail", "smtp", "mandrill", "mxvault", "dkim1024",
        "scph0", "sig1", "protonmail", "pm", "amazonses", "sendgrid",
        "zendesk1", "fm1", "fm2", "fm3",
    ]

    def _query(self, name: str, record_type: str) -> Tuple[bool, List[str]]:
        """Query DNS, returning (ok, values). ok is False on any failure/NODATA."""
        try:
            answers = resolver.query(name, record_type, lifetime=self.QUERY_TIMEOUT)
        except Exception:
            return (False, [])
        return (True, [_rdata_to_string(rdata, record_type) for rdata in answers])

    # -- SPF resolution -----------------------------------------------------

    def _consume_lookup(self, ctx: Dict[str, Any]) -> bool:
        if ctx["lookups"] >= SPF_LOOKUP_LIMIT:
            ctx["limit_exceeded"] = True
            return False
        ctx["lookups"] += 1
        return True

    def _resolve_addresses(self, host: str, ctx: Dict[str, Any]) -> Dict[str, List[str]]:
        result: Dict[str, List[str]] = {"ip4": [], "ip6": []}
        if not is_queryable_domain(host):
            return result
        _, a_records = self._query(host, "A")
        _, aaaa_records = self._query(host, "AAAA")
        for ip in a_records[:MAX_FLATTEN_HOSTS]:
            ctx["ip4"].add(ip)
            result["ip4"].append(ip)
        for ip in aaaa_records[:MAX_FLATTEN_HOSTS]:
            ctx["ip6"].add(ip)
            result["ip6"].append(ip)
        return result

    def _resolve_mx(self, host: str, ctx: Dict[str, Any]) -> Dict[str, List[str]]:
        result: Dict[str, List[str]] = {"ip4": [], "ip6": []}
        if not is_queryable_domain(host):
            return result
        ok, mx_values = self._query(host, "MX")
        if not ok:
            return result
        hosts: List[str] = []
        for data in mx_values[:10]:
            parts = data.strip().split()
            if len(parts) >= 2:
                mx_host = parts[1].rstrip(".")
                if mx_host:
                    hosts.append(mx_host)
        ip4: List[str] = []
        ip6: List[str] = []
        for mx_host in hosts:
            ips = self._resolve_addresses(mx_host, ctx)
            ip4.extend(ips["ip4"])
            ip6.extend(ips["ip6"])
        result["ip4"] = list(dict.fromkeys(ip4))
        result["ip6"] = list(dict.fromkeys(ip6))
        return result

    def _fetch_spf(self, domain: str) -> Optional[Dict[str, Any]]:
        ok, values = self._query(domain, "TXT")
        if not ok:
            return None
        for value in values:
            record = parse_spf(value)
            if record:
                return record
        return None

    def _resolve_child(
        self, target: str, kind: str, ctx: Dict[str, Any], depth: int
    ) -> Dict[str, Any]:
        def error_node(message: str) -> Dict[str, Any]:
            return {
                "domain": target,
                "kind": kind,
                "record": None,
                "error": message,
                "hosts": [],
                "children": [],
            }

        if not is_queryable_domain(target or ""):
            return error_node("Invalid domain in SPF — not queried")
        if target in ctx["visited"]:
            return error_node("Already resolved (loop avoided)")
        if not self._consume_lookup(ctx):
            return error_node(
                f"SPF lookup limit ({SPF_LOOKUP_LIMIT}) exceeded — would permerror"
            )
        ctx["visited"].add(target)
        record = self._fetch_spf(target)
        return self._resolve_node(target, kind, record, ctx, depth + 1)

    def _resolve_node(
        self,
        domain: str,
        kind: str,
        record: Optional[Dict[str, Any]],
        ctx: Dict[str, Any],
        depth: int,
    ) -> Dict[str, Any]:
        node: Dict[str, Any] = {
            "domain": domain,
            "kind": kind,
            "record": record,
            "error": None,
            "hosts": [],
            "children": [],
        }
        if record is None:
            node["error"] = "No SPF record found"
            return node
        if depth > MAX_DEPTH:
            node["error"] = "Maximum include depth exceeded"
            return node

        for mechanism in record["mechanisms"]:
            mtype = mechanism["type"]
            value = mechanism["value"]
            if mtype == "ip4":
                if value:
                    ctx["ip4"].add(value)
            elif mtype == "ip6":
                if value:
                    ctx["ip6"].add(value)
            elif mtype == "a":
                if self._consume_lookup(ctx):
                    host = value or domain
                    ips = self._resolve_addresses(host, ctx)
                    node["hosts"].append({"kind": "a", "host": host, **ips})
            elif mtype == "mx":
                if self._consume_lookup(ctx):
                    host = value or domain
                    ips = self._resolve_mx(host, ctx)
                    node["hosts"].append({"kind": "mx", "host": host, **ips})
            elif mtype in ("ptr", "exists"):
                self._consume_lookup(ctx)
            elif mtype == "include":
                node["children"].append(self._resolve_child(value or "", "include", ctx, depth))
            elif mtype == "redirect":
                node["children"].append(self._resolve_child(value or "", "redirect", ctx, depth))
        return node

    def resolve_spf(self, domain: str, root_record: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively resolve an already-parsed SPF record into a tree + IPs."""
        ctx: Dict[str, Any] = {
            "lookups": 0,
            "limit_exceeded": False,
            "visited": {domain},
            "ip4": set(),
            "ip6": set(),
        }
        tree = self._resolve_node(domain, "root", root_record, ctx, 0)
        flattened = {
            "ip4": sorted(ctx["ip4"]),
            "ip6": sorted(ctx["ip6"]),
            "lookup_count": ctx["lookups"],
            "lookup_limit_exceeded": ctx["limit_exceeded"],
        }
        return {"tree": tree, "flattened": flattened}

    # -- DKIM ---------------------------------------------------------------

    def _build_selector_set(self, selector: Optional[str] = None) -> List[str]:
        selectors = list(self.COMMON_DKIM_SELECTORS)
        if selector:
            candidate = selector.strip().lower()
            if re.match(r"^[a-z0-9_-]+$", candidate) and len(candidate) <= 63:
                selectors = [candidate] + [s for s in selectors if s != candidate]
        return selectors[: self.MAX_DKIM_SELECTORS]

    def _query_dkim_selector(self, domain: str, selector: str) -> Optional[Dict[str, Any]]:
        ok, values = self._query(f"{selector}._domainkey.{domain}", "TXT")
        if not ok:
            return None
        joined = "".join(values)
        if not joined:
            return None
        return parse_dkim(joined, selector)

    def lookup_dkim(self, domain: str, selector: Optional[str] = None) -> Dict[str, Any]:
        """Probe common (and optional explicit) DKIM selectors, filtering wildcards."""
        selectors = self._build_selector_set(selector)
        # A random probe selector no real domain configures; if it answers, a
        # *._domainkey wildcard exists and its echoes must be filtered out.
        probe = f"wildcard-probe-{uuid.uuid4()}"
        found = [
            record
            for record in (self._query_dkim_selector(domain, s) for s in selectors)
            if record
        ]
        wildcard = self._query_dkim_selector(domain, probe)
        records = reconcile_dkim_wildcard(found, wildcard)
        wildcard_out = {**wildcard, "selector": "*"} if wildcard else None
        return {"records": records, "checked_selectors": selectors, "wildcard": wildcard_out}

    # -- top-level report ---------------------------------------------------

    def get_report(self, domain: str, dkim_selector: Optional[str] = None) -> Dict[str, Any]:
        """Return a full email-authentication report for a domain.

        Args:
            domain: The domain to inspect.
            dkim_selector: Optional extra DKIM selector to probe first.

        Returns:
            Dict with spf/spf_tree/spf_flattened, dkim, dmarc, bimi, mx_records.
        """
        domain = domain.strip().lower().rstrip(".")

        spf: Optional[Dict[str, Any]] = None
        ok, txts = self._query(domain, "TXT")
        if ok:
            for txt in txts:
                spf = parse_spf(txt)
                if spf:
                    break

        spf_tree: Optional[Dict[str, Any]] = None
        spf_flattened: Optional[Dict[str, Any]] = None
        if spf:
            resolution = self.resolve_spf(domain, spf)
            spf_tree = resolution["tree"]
            spf_flattened = resolution["flattened"]

        dmarc: Optional[Dict[str, Any]] = None
        ok, dmarc_txts = self._query(f"_dmarc.{domain}", "TXT")
        if ok:
            for txt in dmarc_txts:
                dmarc = parse_dmarc(txt)
                if dmarc:
                    break

        bimi: Optional[Dict[str, Any]] = None
        ok, bimi_txts = self._query(f"default._bimi.{domain}", "TXT")
        if ok:
            for txt in bimi_txts:
                bimi = parse_bimi(txt)
                if bimi:
                    break

        mx_records: List[Dict[str, Any]] = []
        ok, mx_values = self._query(domain, "MX")
        if ok:
            mx_records = [parse_mx_record(value) for value in mx_values]
            mx_records.sort(key=lambda record: record["priority"])

        dkim = self.lookup_dkim(domain, dkim_selector)

        return {
            "domain": domain,
            "spf": spf,
            "spf_tree": spf_tree,
            "spf_flattened": spf_flattened,
            "dkim": dkim,
            "dmarc": dmarc,
            "bimi": bimi,
            "mx_records": mx_records,
        }
