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

    DNS_RECORDS: List[str] = [
        'NONE',
        'A',
        'NS',
        'MD',
        'MF',
        'CNAME',
        'SOA',
        'MB',
        'MG',
        'MR',
        'NULL',
        'WKS',
        'PTR',
        'HINFO',
        'MINFO',
        'MX',
        'TXT',
        'RP',
        'AFSDB',
        'X25',
        'ISDN',
        'RT',
        'NSAP',
        'NSAP-PTR',
        'SIG',
        'KEY',
        'PX',
        'GPOS',
        'AAAA',
        'LOC',
        'NXT',
        'SRV',
        'NAPTR',
        'KX',
        'CERT',
        'A6',
        'DNAME',
        'OPT',
        'APL',
        'DS',
        'SSHFP',
        'IPSECKEY',
        'RRSIG',
        'NSEC',
        'DNSKEY',
        'DHCID',
        'NSEC3',
        'NSEC3PARAM',
        'TLSA',
        'HIP',
        'CDS',
        'CDNSKEY',
        'CSYNC',
        'SPF',
        'UNSPEC',
        'EUI48',
        'EUI64',
        'TKEY',
        'TSIG',
        'IXFR',
        'AXFR',
        'MAILB',
        'MAILA',
        'ANY',
        'URI',
        'CAA',
        'TA',
        'DLV',
    ]

    def _is_valid_ip(self, ip_string: str) -> bool:
        try:
            ipaddress.ip_address(ip_string)
            return True
        except ValueError:
            return False

    def _parse_txt_record(self, record: str) -> List[str]:
        return_list: List[str] = []
        for address in record.split("ip4:"):
            if self._is_valid_ip(address.strip()):
                return_list.append(address.strip())
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
                answers = resolver.query(domain, item)
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
            host = repr(data[0])
            return host
        except Exception:
            return ""

    def get_fqdn(self, ip_address: str) -> str:
        """This method returns the 'True Host' name for a given IP address

        Args:
            ip_address (str): The IP address to lookup.

        Returns:
            str: The FQDN assocaited with a given IP.
        """
        try:
            data = socket.gethostbyaddr(ip_address)
            host = repr(data[0])
            return host
        except Exception:
            return ""

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
        ip_list = list(set(ip_list))
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
