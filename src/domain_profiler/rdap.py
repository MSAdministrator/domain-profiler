import requests

from domain_profiler.base import Base


class RDAP(Base):

    BASE_URL: str = "https://www.rdap.net"

    def ip(self, ipaddress: str) -> dict:
        return requests.request(
            "GET",
            url=f"{self.BASE_URL}/ip/{ipaddress}",
        ).json()

    def domain(self, domain: str) -> dict:
        return requests.request(
            "GET",
            url=f"{self.BASE_URL}/domain/{domain}",
        ).json()

    def autnum(self, autnum: str) -> dict:
        return requests.request(
            "GET",
            url=f"{self.BASE_URL}/autnum/{autnum}",
        ).json()
