"""DNS analysis and profiling functionality."""

import ipaddress
import socket
from typing import Any, Dict, List, Union

from dns import (
    resolver, 
    reversename
)

from domain_profiler.base import Base


class DNSCheck(Base):
    """DNS checking and analysis class."""

    # The record types worth querying for a domain profile. The full IANA
    # registry contains ~70 types, but most are obsolete (MD, MF), meta/transfer
    # types (AXFR, IXFR, OPT, ANY) that a recursive resolver will refuse, or
    # DNSSEC internals with little profiling value. Querying only the useful
    # types keeps a lookup to a handful of fast queries instead of ~70 that
    # mostly time out.
    DNS_RECORDS: List[str] = [
        'A',
        'AAAA',
        'MX',
        'TXT',
        'CNAME',
        'NS',
        'SOA',
        'SRV',
        'CAA',
        'PTR',
        'NAPTR',
        'DNSKEY',
    ]

    # Per-query timeout (seconds) so a single unresponsive record type can't
    # stall the whole report.
    QUERY_TIMEOUT: float = 5.0

    def _is_valid_ip(self, ip_string: str) -> bool:
        try:
            ipaddress.ip_address(ip_string)
            return True
        except ValueError:
            return False

    def _parse_txt_record(self, record: str) -> List[str]:
        """Extract IPs from an SPF-style TXT record.

        SPF records are whitespace-separated mechanisms (e.g.
        ``v=spf1 ip4:1.2.3.4 ip4:5.6.7.8 -all``). Splitting only on ``ip4:``
        left the trailing tokens attached to each address (``"5.6.7.8 -all"``),
        which then failed IP validation and were dropped. Tokenize on
        whitespace first, then strip the ``ip4:``/``ip6:`` prefix from each
        token before validating.
        """
        return_list: List[str] = []
        for token in record.replace('"', ' ').split():
            candidate = token
            for prefix in ("ip4:", "ip6:"):
                if candidate.startswith(prefix):
                    candidate = candidate[len(prefix):]
                    break
            if self._is_valid_ip(candidate):
                return_list.append(candidate)
        return return_list

    def get_dns_info(self, domain: str) -> Dict[str, List[str]]:
        """Checks all known records for a given domain.

        Args:
            domain (str): A domain to lookup

        Returns:
            Dict[str, List[str]]: A dict of records to results.
        """
        return_dict: Dict[str, List[str]] = {}
        for item in self.DNS_RECORDS:
            try:
                answers = resolver.query(
                    domain, item, lifetime=self.QUERY_TIMEOUT
                )
                if answers:
                    if item not in return_dict:
                        return_dict[item] = []
                    for server in answers:
                        text = server.to_text()
                        if item == "TXT":
                            parsed_ips = self._parse_txt_record(text)
                            if parsed_ips:
                                return_dict[item].extend(parsed_ips)
                            continue
                        if isinstance(text, list):
                            for t in text:
                                return_dict[item].append(t)
                        else:
                            return_dict[item].append(text)
            except Exception:
                pass
        return return_dict

    def get_reversename(self, ip_address: str) -> Dict[str, List[str]]:
        """Gets the reverse name of a given IP address and checks all DNS records
        For that resolved domain

        Args:
            ip_address (str): IP Address to get the reverse domain of

        Returns:
            Dict[str, List[str]]: A dictionary of record types and its corresponding values
        """
        try:
            addr = reversename.from_address(ip_address)
            return self.get_dns_info(str(addr))
        except Exception:
            return {}

    def get_ip(self, domain: str) -> str:
        """
        This method returns the first IP address string that responds as the given domain name

        Args:
            domain (str): The domain to lookup

        Returns:
            str: A IP address associated with the given domain.
        """
        try:
            return socket.gethostbyname(domain)
        except Exception:
            return ""

    def get_ip_x(self, domain: str) -> List[str]:
        """This method returns an array containing
        one or more IP address strings that respond
        as the given domain name

        Args:
            domain (str): The domain to lookup

        Returns:
            List[str]: A list of IPs associated with a given domain.
        """
        try:
            return socket.gethostbyname_ex(domain)[2]
        except Exception:
            return []

    def get_host(self, ip_address: str) -> str:
        """This method returns the 'True Host' name for a given IP address.

        Args:
            ip_address (str): IP Address to lookup

        Returns:
            str: The host for a given IP.
        """
        try:
            data = socket.gethostbyaddr(ip_address)
            return data[0]
        except Exception:
            return ""

    def get_fqdn(self, ip_address: str) -> str:
        """This method returns the 'True Host' name for a given IP address

        Args:
            ip_address (str): The IP address to lookup.

        Returns:
            str: The FQDN assocaited with a given IP.
        """
        return self.get_host(ip_address)

    def get_aliases(self, domain: str) -> List[str]:
        """This method returns an array containing a list of aliases for the given domain

        Args:
            domain (str): The domain to lookup.

        Returns:
            List[str]: A list of aliases associated with a domain.
        """
        try:
            return socket.gethostbyname_ex(domain)[1]
        except Exception:
            return []

    def is_ip_in_cidr(self, ip: str, cidr: str) -> bool:
        """
        Check if an IP address is within a CIDR range
        
        Args:
            ip: IP address to check
            cidr: CIDR range in format "x.x.x.x/y"
            
        Returns:
            bool: True if IP is in CIDR range, False otherwise
        """
        try:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr)
        except ValueError:
            return False

    def get_report(self, domain: str) -> Dict[str, Any]:
        """Return a report of data about a given domain.

        Args:
            domain (str): The domain to lookup

        Returns:
            Dict[str, Any]: A result map of attributes associated with a given domain.
        """
        ip_list: List[str] = []
        ip_list.append(self.get_ip(domain=domain))
        ip_list.extend(self.get_ip_x(domain=domain))
        # Drop failed lookups (get_ip returns "" on failure) so we don't emit a
        # bogus empty-string "IP" entry and run host/reverse lookups against it.
        ip_list = [ip for ip in set(ip_list) if ip]
        ip_dict: Dict[str, Dict[str, Union[str, Dict[str, List[str]]]]] = {}
        for ip in ip_list:
            if ip not in ip_dict:
                ip_dict[ip] = {}
            ip_dict[ip].update({
                "host": self.get_host(ip_address=ip),
                "fqdn": self.get_fqdn(ip_address=ip),
                "reverse": self.get_reversename(ip_address=ip)
            })
        return {
            "domain": domain,
            "aliases": self.get_aliases(domain=domain),
            "ips": ip_dict,
            "dns": self.get_dns_info(domain=domain)
        }
