"""Website analysis and profiling functionality."""

import re
import codecs
from datetime import date
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse, urlunparse, urljoin, ParseResult

import mmh3
import whois
import pendulum
from requests_html import HTMLSession, HTMLResponse

from bs4 import BeautifulSoup, Tag

from domain_profiler.base import Base


class Url(Base):
    """URL analysis and website profiling class."""

    session: HTMLSession = HTMLSession()
    content_types: List[str] = [
        'application/zip',
        'application/gzip',
        'application/octet-stream',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    ]
    response: Optional[HTMLResponse] = None

    def __init__(self, url: str, **kwargs: Any) -> None:
        """Initialize URL analysis.
        
        Args:
            url: The URL to analyze
            **kwargs: Additional keyword arguments
        """
        self._original_url: str = url
        self._parsed_url: ParseResult = urlparse(self._original_url)
        self.response: Optional[HTMLResponse] = None
        
        try:
            self.response = self.session.get(self._original_url, verify=False, timeout=5)
        except Exception:
            try:
                # Retry over http. Rebuild only the scheme via urlunparse so we
                # don't corrupt hosts/paths that happen to contain "https"
                # (e.g. https://httpsecure.example) the way str.replace would.
                http_url = urlunparse(self._parsed_url._replace(scheme='http'))
                self.response = self.session.get(
                    http_url,
                    verify=False,
                    timeout=5
                )
            except Exception:
                self.__logger.info(f"{self._original_url} does not seem up or is not accepting connections.")  # type: ignore[attr-defined]
        
        self._whois: Optional[Dict[str, Any]] = whois.whois(self._parsed_url.netloc)

    def get_redirects(self) -> List[str]:
        """Get list of redirect URLs from response history.
        
        Returns:
            List of redirect URLs
        """
        return_list: List[str] = []
        if self.response:
            for response in self.response.history:
                return_list.append(response.url)
        return return_list

    @staticmethod
    def _coerce_whois_date(value: Any) -> Any:
        """Return a single datetime from a WHOIS date field.

        python-whois returns date fields (creation_date, updated_date, ...) as
        either a single datetime or a list of datetimes depending on the
        registrar. Callers assuming one shape crash (and silently return {})
        on the other. Normalize to the most recent datetime here.
        """
        if isinstance(value, (list, tuple)):
            return value[-1] if value else None
        return value

    def domain_registration_length(self) -> Dict[str, Union[int, str]]:
        """Calculate domain registration length from WHOIS data.

        Returns:
            Dictionary with registration length in various formats
        """
        try:
            if self._whois and self._whois.get('updated_date'):
                updated = self._coerce_whois_date(self._whois['updated_date'])
                updated_date = pendulum.instance(updated)
                difference = updated_date.diff()
                return {
                    'in_minutes': difference.in_minutes(),
                    'in_hours': difference.in_hours(),
                    'in_days': difference.in_days(),
                    'human': difference.in_words()
                }
        except Exception:
            pass
        return {}

    def get_favicons(self) -> List[Dict[str, Union[str, int]]]:
        """Extract and analyze favicons from the website.
        
        Returns:
            List of favicon information with href and hash
        """
        return_list: List[Dict[str, Union[str, int]]] = []
        if self.response:
            results = self.response.html.find('link')
            if results:
                for item in results:
                    if item.attrs.get('rel') and 'icon' in item.attrs['rel']:
                        try:
                            # Favicon hrefs are commonly relative ("/favicon.ico").
                            # Resolve against the fetched URL so session.get gets an
                            # absolute URL instead of raising MissingSchema.
                            base = self.response.url if self.response else self._original_url
                            href = urljoin(base, item['href'])
                            response = self.session.get(href)
                            favicon = codecs.encode(response.content, 'base64')
                            return_list.append({
                                'href': href,
                                'hash': mmh3.hash(favicon)
                            })
                        except Exception:
                            pass
        return return_list

    def domain_age(self) -> Dict[str, Union[int, str]]:
        """Calculate domain age from WHOIS creation date.
        
        Returns:
            Dictionary with domain age in various formats
        """
        try:
            if self._whois and self._whois.get('creation_date'):
                created = self._coerce_whois_date(self._whois['creation_date'])
                creation_date = pendulum.instance(created)
                difference = creation_date.diff()
                return {
                    'in_minutes': difference.in_minutes(),
                    'in_hours': difference.in_hours(),
                    'in_days': difference.in_days(),
                    'human': difference.in_words()
                }
        except Exception:
            pass
        return {}

    @classmethod
    def _jsonify(cls, value: Any) -> Any:
        """Recursively convert WHOIS data into JSON-serializable values.

        python-whois returns datetime objects (and nested lists/dicts of them),
        which json.dumps cannot serialize. Convert datetimes to ISO strings so
        the dict honors this method's JSON-serializable contract.
        """
        if isinstance(value, date):  # datetime is a subclass of date
            return value.isoformat()
        if isinstance(value, dict):
            return {k: cls._jsonify(v) for k, v in value.items()}
        if isinstance(value, (list, tuple, set)):
            return [cls._jsonify(v) for v in value]
        return value

    def to_json(self) -> Dict[str, Any]:
        """Convert URL analysis to JSON-serializable dictionary.

        Returns:
            Dictionary containing all analysis results
        """
        return_dict: Dict[str, Any] = {}
        for key, val in self._parsed_url._asdict().items():
            if val:
                return_dict[key] = val
        
        return_dict.update({
            'url': self._original_url,
            'is_alive': self.is_alive,
            'is_file': self.is_file,
            'has_ip': self.has_ip,
            'has_https': self.has_https,
            'is_abnormal_url': self.is_abnormal_url,
            'has_at_symbol': self.has_at_symbol,
            'has_double_slash': self.has_double_slash,
            'has_non_standard_port': self.has_non_standard_port,
            'has_popup_window': self.has_popup_window,
            'has_suspicious_forms': self.has_suspicious_forms,
            'using_sub_domains': self.using_sub_domains,
            'whois': self._jsonify(self._whois),
            'domain_age': self.domain_age(),
            'domain_registration_length': self.domain_registration_length(),
            'favicons': self.get_favicons(),
            'title': self.title,
        })
        return return_dict

    @property
    def is_alive(self) -> bool:
        """Check if the website is accessible and responding.
        
        Returns:
            True if website is alive, False otherwise
        """
        if self.response and self.response.ok:
            return True
        return False

    @property
    def is_file(self) -> bool:
        """Check if the URL points to a file rather than a webpage.
        
        Returns:
            True if URL is a file, False otherwise
        """
        if self.response and self.response.ok:
            if 'content-type' in self.response.headers:
                if self.response.headers['content-type'] in self.content_types:
                    return True
                elif self.response.url.rsplit('.')[-1] in self.extensions:
                    return True
        return False

    @property
    def has_ip(self) -> bool:
        """Check if the URL uses an IP address instead of domain name.
        
        Returns:
            True if URL contains IP address, False otherwise
        """
        try:
            ip_match = re.match(
                r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", 
                self._parsed_url.netloc
            )
            if ip_match:
                return True
        except Exception:
            pass
        return False

    @property
    def has_at_symbol(self) -> bool:
        """Check if URL contains @ symbol (potential phishing indicator).
        
        Returns:
            True if URL contains @, False otherwise
        """
        try:
            if '@' in self._original_url:
                return True
            else:
                return False
        except Exception:
            pass
        return False

    @property
    def has_double_slash(self) -> bool:
        """Check if URL contains double slashes (potential obfuscation).
        
        Returns:
            True if URL contains //, False otherwise
        """
        try:
            if '//' in self._original_url:
                return True
            else:
                return False
        except Exception:
            pass
        return False

    @property
    def has_non_standard_port(self) -> bool:
        """Check if URL uses non-standard ports.
        
        Returns:
            True if non-standard port is used, False otherwise
        """
        try:
            if self._parsed_url.port is None or self._parsed_url.port == 80 or self._parsed_url.port == 443:
                return False
            else:
                return True
        except Exception:
            pass
        return False

    @property
    def has_https(self) -> bool:
        """Check if website supports HTTPS.
        
        Returns:
            True if HTTPS is supported, False otherwise
        """
        return_bool = False
        if self._parsed_url.scheme == 'https':
            return_bool = True
        else:
            try:
                https_domain = self.session.get(f'https://{self._parsed_url.netloc}')
                if https_domain.ok:
                    return_bool = True
                else:
                    return_bool = False
            except Exception:
                return_bool = False
        return return_bool

    @property
    def has_suspicious_forms(self) -> Optional[bool]:
        """Check for suspicious form attributes that may indicate phishing.
        
        Returns:
            True if suspicious forms found, False if safe, None if no response
        """
        if self.response:
            try:
                soup = BeautifulSoup(self.response.content, 'html.parser')
                forms = soup.find_all('form')
                found_form = False
                for form in forms:
                    if isinstance(form, Tag):
                        found_form = True
                        action = form.get('action')
                        # Any suspicious form makes the page suspicious, so keep
                        # scanning until we find one instead of deciding on the
                        # first form (which let a benign first form mask a later
                        # phishing form).
                        if action == "" or action is None or action == "about:blank":
                            return True
                if found_form:
                    return False
            except Exception:
                pass
        return None

    @property
    def is_abnormal_url(self) -> Optional[bool]:
        """Check if URL structure is abnormal compared to WHOIS domain.
        
        Returns:
            True if abnormal, False if normal, None if cannot determine
        """
        try:
            if self._whois and self._whois.get('domain_name'):
                domain_names = self._whois['domain_name']
                if isinstance(domain_names, list):
                    domain_name = domain_names[0]
                else:
                    domain_name = domain_names
                
                # Plain substring check: the WHOIS domain name is data, not a
                # pattern. Using it as a regex let "." match any character
                # (false negatives) and could raise re.error on metacharacters.
                if domain_name.lower() not in self._original_url.lower():
                    return True
                else:
                    return False
        except Exception:
            pass
        return None

    @property
    def using_sub_domains(self) -> Optional[bool]:
        """Check if URL uses excessive subdomains (potential obfuscation).
        
        Returns:
            True if using many subdomains, False otherwise, None if error
        """
        temp = self._original_url
        try:
            if temp.startswith('http://www.'):
                temp = temp[11:]
            elif temp.startswith('https://www.'):
                temp = temp[12:]
            elif temp.startswith('www.'):
                temp = temp[4:]
            
            if temp.count('.') > 3:
                return True
            else:
                return False
        except Exception:
            pass
        return None

    @property
    def has_popup_window(self) -> bool:
        """Check if website contains popup window JavaScript.
        
        Returns:
            True if popups detected, False otherwise
        """
        if self.response and self.response.ok:
            try:
                self.response.html.render()
                for tag in self.response.html.find('script'):
                    # Group the alternatives so the pattern matches any of the
                    # popup calls. Without the group, top-level | made this
                    # ".*open(" OR "alert(" OR "confirm(" OR "prompt(.*", which
                    # matched benign scripts containing e.g. "alert(" anywhere.
                    match_obj = re.search(r'(open|alert|confirm|prompt)\(', tag.text)
                    if match_obj:
                        return True
            except Exception:
                pass
        return False

    @property
    def subdirectory_list(self) -> List[str]:
        """Generate list of potential subdirectories from URL path.
        
        Returns:
            List of subdirectory URLs
        """
        sub_list: List[str] = []
        part_string = '' 
        part_string_slash = ''
        
        for part in self._parsed_url.path.split('/'):
            if part and part.rsplit('.')[-1] not in self.extensions:
                part_string += f'/{part}'
                sub_list.append(
                    urlunparse((
                        self._parsed_url.scheme,
                        self._parsed_url.netloc,
                        part_string,
                        None,
                        None,
                        None
                    ))
                )
                if part_string_slash == '':
                    part_string_slash += f'/{part}/'
                else:
                    part_string_slash += f'{part}/'
                sub_list.append(
                    urlunparse((
                        self._parsed_url.scheme,
                        self._parsed_url.netloc,
                        part_string_slash,
                        None,
                        None,
                        None
                    ))
                )
        return sub_list

    @property
    def subdirectory_zip_list(self) -> List[str]:
        """Generate list of potential ZIP files from URL subdirectories.
        
        Returns:
            List of potential ZIP file URLs
        """
        sub_list: List[str] = []
        part_string = ''

        for part in self._parsed_url.path.split('/'):
            if part and part.rsplit('.')[-1] not in self.extensions:
                part_string += f'/{part}'
                sub_list.append(
                    urlunparse((
                        self._parsed_url.scheme,
                        self._parsed_url.netloc,
                        part_string + '.zip',
                        None,
                        None,
                        None
                    ))
                )
        return sub_list

    @property
    def title(self) -> str:
        """Extract page title from HTML content.
        
        Returns:
            Page title or empty string if not found
        """
        try:
            if self.response and self.response.content:
                soup = BeautifulSoup(self.response.content, 'html.parser')
                title_tag = soup.find('title')
                if title_tag and title_tag.get_text():
                    return title_tag.get_text().strip()
        except Exception:
            pass
        return ""
