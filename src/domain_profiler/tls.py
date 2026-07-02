"""TLS/SSL certificate inspection.

The certificate is the one artifact an attacker must present to serve HTTPS, and
it exposes issuer, validity window, covered names, and crypto strength in a
single handshake. This module connects to a host, retrieves the leaf
certificate, and extracts the security-relevant fields — flagging a self-signed
cert, an expired/very-fresh cert, a SAN that does not cover the hostname, or a
weak key/signature.
"""

import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from domain_profiler.base import Base


class TLSInspector(Base):
    """Connect to a host and inspect its TLS leaf certificate."""

    TIMEOUT: float = 5.0
    # Certs younger than this (days) are noted — attackers provision TLS right
    # before a phishing campaign, so a brand-new cert on a suspect domain adds
    # weight (weak alone, strong combined with a lookalike name).
    FRESH_CERT_DAYS: int = 30
    MIN_RSA_BITS: int = 2048

    def _fetch_cert_der(self, host: str, port: int) -> Optional[bytes]:
        """Fetch the leaf certificate as DER bytes without validating the chain.

        Validation is intentionally disabled so we can inspect certs on hosts
        that present self-signed / expired / mismatched certificates (exactly
        the suspicious cases we want to report).
        """
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=self.TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    return ssock.getpeercert(binary_form=True)
        except Exception:
            return None

    def _chain_trusted(self, host: str, port: int) -> bool:
        """Return True if the cert validates against the system trust store.

        A normal verified handshake proves trust + hostname match in one step.
        """
        context = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=self.TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=host):
                    return True
        except Exception:
            return False

    @staticmethod
    def _name_attr(name: x509.Name, oid: Any) -> Optional[str]:
        try:
            attrs = name.get_attributes_for_oid(oid)
            if not attrs:
                return None
            value = attrs[0].value
            return value.decode("utf-8", "replace") if isinstance(value, bytes) else value
        except Exception:
            return None

    @staticmethod
    def _san_dns_names(cert: x509.Certificate) -> List[str]:
        try:
            ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            san = ext.value
            assert isinstance(san, x509.SubjectAlternativeName)
            return san.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            return []
        except Exception:
            return []

    @staticmethod
    def _san_covers(host: str, san: List[str]) -> bool:
        """Check whether host is covered by the SAN list (incl. wildcards)."""
        host = host.lower().rstrip(".")
        for entry in san:
            entry = entry.lower().rstrip(".")
            if entry == host:
                return True
            if entry.startswith("*."):
                # A wildcard matches exactly one label to the left.
                suffix = entry[1:]  # ".example.com"
                left, _, rest = host.partition(".")
                if left and f".{rest}" == suffix:
                    return True
        return False

    def _key_info(self, cert: x509.Certificate) -> Dict[str, Any]:
        info: Dict[str, Any] = {"type": None, "bits": None, "weak": False}
        try:
            key = cert.public_key()
        except Exception:
            return info
        if isinstance(key, rsa.RSAPublicKey):
            info["type"] = "RSA"
            info["bits"] = key.key_size
            info["weak"] = key.key_size < self.MIN_RSA_BITS
        elif isinstance(key, ec.EllipticCurvePublicKey):
            info["type"] = "EC"
            info["bits"] = key.key_size
        elif isinstance(key, dsa.DSAPublicKey):
            info["type"] = "DSA"
            info["bits"] = key.key_size
            info["weak"] = True  # DSA is deprecated for TLS
        else:
            info["type"] = type(key).__name__
        return info

    def inspect(self, host: str, port: int = 443) -> Dict[str, Any]:
        """Inspect the TLS leaf certificate presented by host:port.

        Args:
            host: Hostname to connect to (SNI + validation target).
            port: TLS port (default 443).

        Returns:
            A dict with issuer/subject, validity window, SAN, key info, and
            derived flags (self_signed, expired, fresh, san_mismatch,
            chain_trusted, weak_key). ``error`` is set if no cert was retrieved.
        """
        result: Dict[str, Any] = {
            "host": host,
            "port": port,
            "error": None,
            "issuer": None,
            "issuer_org": None,
            "subject": None,
            "not_before": None,
            "not_after": None,
            "serial_number": None,
            "signature_algorithm": None,
            "subject_alt_names": [],
            "key": {"type": None, "bits": None, "weak": False},
            "self_signed": None,
            "expired": None,
            "fresh": None,
            "age_days": None,
            "san_mismatch": None,
            "chain_trusted": None,
            "notes": [],
        }

        der = self._fetch_cert_der(host, port)
        if der is None:
            result["error"] = "Could not retrieve TLS certificate"
            return result

        try:
            cert = x509.load_der_x509_certificate(der)
        except Exception as exc:
            result["error"] = f"Certificate parse failed: {exc}"
            return result

        result["issuer"] = self._name_attr(cert.issuer, NameOID.COMMON_NAME)
        result["issuer_org"] = self._name_attr(cert.issuer, NameOID.ORGANIZATION_NAME)
        result["subject"] = self._name_attr(cert.subject, NameOID.COMMON_NAME)
        result["serial_number"] = str(cert.serial_number)
        try:
            result["signature_algorithm"] = cert.signature_hash_algorithm.name  # type: ignore[union-attr]
        except Exception:
            result["signature_algorithm"] = None

        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        result["not_before"] = not_before.isoformat()
        result["not_after"] = not_after.isoformat()

        now = datetime.now(timezone.utc)
        result["expired"] = now > not_after or now < not_before
        age = (now - not_before).days
        result["age_days"] = age
        result["fresh"] = 0 <= age < self.FRESH_CERT_DAYS

        san = self._san_dns_names(cert)
        result["subject_alt_names"] = san
        result["san_mismatch"] = not self._san_covers(host, san) if san else True

        result["key"] = self._key_info(cert)

        # Self-signed: subject == issuer and it verifies against its own key.
        result["self_signed"] = self._is_self_signed(cert)

        result["chain_trusted"] = self._chain_trusted(host, port)

        self._add_notes(result)
        return result

    @staticmethod
    def _is_self_signed(cert: x509.Certificate) -> bool:
        if cert.subject != cert.issuer:
            return False
        try:
            cert.verify_directly_issued_by(cert)
            return True
        except Exception:
            # Names match but signature check failed — still effectively
            # self-issued/suspicious; report as self-signed.
            return True

    def _add_notes(self, result: Dict[str, Any]) -> None:
        if result["self_signed"]:
            result["notes"].append("Self-signed certificate")
        if result["expired"]:
            result["notes"].append("Certificate is expired or not yet valid")
        if result["fresh"]:
            result["notes"].append(
                f"Certificate issued {result['age_days']} days ago (very fresh)"
            )
        if result["san_mismatch"]:
            result["notes"].append("Hostname not covered by certificate SAN")
        if result["key"].get("weak"):
            result["notes"].append(
                f"Weak key: {result['key'].get('type')} {result['key'].get('bits')} bits"
            )
        if result["chain_trusted"] is False and not result["self_signed"]:
            result["notes"].append("Certificate chain does not validate to a trusted root")
