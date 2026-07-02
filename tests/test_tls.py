"""Tests for TLS certificate inspection.

Certificates are built in-memory with `cryptography` and fed to the inspector by
mocking the network fetch, so the real parsing/flagging path runs offline.
"""

import datetime
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from domain_profiler.tls import TLSInspector


def _der(
    subject_cn="example.com",
    issuer_cn="Example CA",
    san=("example.com",),
    days_ago_start=100,
    days_valid=365,
    key_bits=2048,
    self_signed=False,
):
    """Build a certificate in-memory and return its DER bytes."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_bits)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    issuer = subject if self_signed else x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn),
         x509.NameAttribute(NameOID.ORGANIZATION_NAME, issuer_cn)]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=days_ago_start))
        .not_valid_after(
            now - datetime.timedelta(days=days_ago_start)
            + datetime.timedelta(days=days_valid)
        )
    )
    if san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in san]), critical=False
        )
    cert = builder.sign(key, hashes.SHA256())
    return cert.public_bytes(Encoding.DER)


class TestTLSInspector:
    def test_error_when_no_cert(self):
        t = TLSInspector()
        with patch.object(t, "_fetch_cert_der", return_value=None):
            r = t.inspect("example.com")
        assert r["error"] is not None

    def test_valid_cert_fields(self):
        t = TLSInspector()
        der = _der(subject_cn="example.com", issuer_cn="Real CA", san=("example.com", "www.example.com"))
        with patch.object(t, "_fetch_cert_der", return_value=der):
            with patch.object(t, "_chain_trusted", return_value=True):
                r = t.inspect("example.com")
        assert r["error"] is None
        assert r["subject"] == "example.com"
        assert r["issuer_org"] == "Real CA"
        assert "www.example.com" in r["subject_alt_names"]
        assert r["self_signed"] is False
        assert r["expired"] is False
        assert r["san_mismatch"] is False
        assert r["chain_trusted"] is True
        assert r["key"]["type"] == "RSA"
        assert r["key"]["bits"] == 2048
        # signature_algorithm is the full algorithm; signature_hash is the digest.
        assert r["signature_algorithm"] == "sha256WithRSAEncryption"
        assert r["signature_hash"] == "sha256"

    def test_self_signed_flagged(self):
        t = TLSInspector()
        der = _der(subject_cn="badssl", self_signed=True, san=("example.com",))
        with patch.object(t, "_fetch_cert_der", return_value=der):
            with patch.object(t, "_chain_trusted", return_value=False):
                r = t.inspect("example.com")
        assert r["self_signed"] is True
        assert any("Self-signed" in n for n in r["notes"])

    def test_expired_flagged(self):
        t = TLSInspector()
        # Started 400 days ago, valid 90 days → long expired.
        der = _der(days_ago_start=400, days_valid=90, san=("example.com",))
        with patch.object(t, "_fetch_cert_der", return_value=der):
            with patch.object(t, "_chain_trusted", return_value=False):
                r = t.inspect("example.com")
        assert r["expired"] is True
        assert any("expired" in n.lower() for n in r["notes"])

    def test_fresh_cert_flagged(self):
        t = TLSInspector()
        der = _der(days_ago_start=3, days_valid=90, san=("example.com",))
        with patch.object(t, "_fetch_cert_der", return_value=der):
            with patch.object(t, "_chain_trusted", return_value=True):
                r = t.inspect("example.com")
        assert r["fresh"] is True
        assert any("fresh" in n.lower() for n in r["notes"])

    def test_san_mismatch_flagged(self):
        t = TLSInspector()
        der = _der(san=("other.com", "www.other.com"))
        with patch.object(t, "_fetch_cert_der", return_value=der):
            with patch.object(t, "_chain_trusted", return_value=False):
                r = t.inspect("example.com")
        assert r["san_mismatch"] is True
        assert any("SAN" in n for n in r["notes"])

    def test_wildcard_san_covers_host(self):
        t = TLSInspector()
        der = _der(san=("*.example.com",))
        with patch.object(t, "_fetch_cert_der", return_value=der):
            with patch.object(t, "_chain_trusted", return_value=True):
                r = t.inspect("www.example.com")
        assert r["san_mismatch"] is False

    def test_weak_key_flagged(self):
        t = TLSInspector()
        der = _der(key_bits=1024, san=("example.com",))
        with patch.object(t, "_fetch_cert_der", return_value=der):
            with patch.object(t, "_chain_trusted", return_value=True):
                r = t.inspect("example.com")
        assert r["key"]["weak"] is True
        assert any("Weak key" in n for n in r["notes"])

    def test_san_covers_helper(self):
        assert TLSInspector._san_covers("example.com", ["example.com"]) is True
        assert TLSInspector._san_covers("www.example.com", ["*.example.com"]) is True
        assert TLSInspector._san_covers("a.b.example.com", ["*.example.com"]) is False
        assert TLSInspector._san_covers("other.com", ["example.com"]) is False

    def test_inherits_from_base(self):
        from domain_profiler.base import Base
        assert isinstance(TLSInspector(), Base)
