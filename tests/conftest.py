"""Pytest configuration and fixtures for domain-profiler tests."""

import pytest
from unittest.mock import Mock, MagicMock
from dns import resolver
from requests_html import HTMLResponse, HTMLSession


@pytest.fixture
def sample_domain():
    """Sample domain for testing."""
    return "example.com"


@pytest.fixture
def sample_url():
    """Sample URL for testing."""
    return "https://example.com"


@pytest.fixture
def sample_ip():
    """Sample IP address for testing."""
    return "93.184.216.34"


@pytest.fixture
def mock_dns_response():
    """Mock DNS response data."""
    mock_response = Mock()
    mock_response.to_text.return_value = "93.184.216.34"
    return [mock_response]


@pytest.fixture
def mock_whois_data():
    """Mock WHOIS data."""
    return {
        'domain_name': ['EXAMPLE.COM'],
        'registrar': 'IANA',
        'creation_date': '1995-08-14 04:00:00',
        'updated_date': '2023-08-14 07:01:31',
        'expiration_date': '2024-08-13 04:00:00',
        'name_servers': ['A.IANA-SERVERS.NET', 'B.IANA-SERVERS.NET'],
        'status': 'clientDeleteProhibited',
        'emails': 'domains@iana.org'
    }


@pytest.fixture
def mock_html_response():
    """Mock HTML response for testing."""
    mock_response = Mock(spec=HTMLResponse)
    mock_response.ok = True
    mock_response.status_code = 200
    mock_response.url = "https://example.com"
    mock_response.headers = {
        'content-type': 'text/html; charset=utf-8'
    }
    mock_response.content = b'<html><head><title>Example Domain</title></head><body>Test content</body></html>'
    mock_response.text = mock_response.content.decode('utf-8')
    mock_response.history = []
    
    # Mock HTML parsing
    mock_html = Mock()
    mock_html.find.return_value = []
    mock_response.html = mock_html
    
    return mock_response


@pytest.fixture
def mock_session():
    """Mock HTMLSession for testing."""
    mock_session = Mock(spec=HTMLSession)
    return mock_session


@pytest.fixture
def sample_dns_records():
    """Sample DNS records data."""
    return {
        'A': ['93.184.216.34'],
        'AAAA': ['2606:2800:220:1:248:1893:25c8:1946'],
        'MX': ['0 .'],
        'NS': ['a.iana-servers.net.', 'b.iana-servers.net.'],
        'TXT': ['v=spf1 -all'],
        'SOA': ['a.iana-servers.net. nstld.verisign-grs.com. 2023071800 1800 900 604800 86400']
    }


@pytest.fixture
def mock_resolver_query(monkeypatch):
    """Mock DNS resolver query."""
    def mock_query(domain, record_type):
        mock_answer = Mock()
        if record_type == 'A':
            mock_answer.to_text.return_value = '93.184.216.34'
        elif record_type == 'MX':
            mock_answer.to_text.return_value = '0 .'
        elif record_type == 'NS':
            mock_answer.to_text.return_value = 'a.iana-servers.net.'
        else:
            mock_answer.to_text.return_value = f'mock-{record_type}-record'
        return [mock_answer]
    
    monkeypatch.setattr(resolver, 'query', mock_query)
    return mock_query


@pytest.fixture
def mock_socket_operations(monkeypatch):
    """Mock socket operations for testing."""
    import socket
    
    def mock_gethostbyname(hostname):
        return "93.184.216.34"
    
    def mock_gethostbyname_ex(hostname):
        return (hostname, [], ["93.184.216.34"])
    
    def mock_gethostbyaddr(ip):
        return ("example.com", [], [])
    
    monkeypatch.setattr(socket, 'gethostbyname', mock_gethostbyname)
    monkeypatch.setattr(socket, 'gethostbyname_ex', mock_gethostbyname_ex)
    monkeypatch.setattr(socket, 'gethostbyaddr', mock_gethostbyaddr)


@pytest.fixture
def mock_requests_session(monkeypatch):
    """Mock requests-html session."""
    def mock_get(url, **kwargs):
        mock_response = Mock()
        mock_response.ok = True
        mock_response.status_code = 200
        mock_response.url = url
        mock_response.headers = {'content-type': 'text/html'}
        mock_response.content = b'<html><title>Test</title></html>'
        mock_response.history = []
        
        # Mock HTML object
        mock_html = Mock()
        mock_html.find.return_value = []
        mock_response.html = mock_html
        
        return mock_response
    
    mock_session = Mock()
    mock_session.get = mock_get
    
    from requests_html import HTMLSession
    monkeypatch.setattr(HTMLSession, '__new__', lambda cls: mock_session)
    return mock_session 