import secrets
import ssl
from datetime import UTC, datetime
from pathlib import Path
from typing import ClassVar, Final, TypedDict, final

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import (
    Certificate,
    load_pem_x509_certificates,
)


class CertificateInfo(TypedDict):
    subject: dict[str, str]
    issuer: dict[str, str]
    serial: int
    fingerprint: str
    not_before: float
    not_after: float
    extensions: dict[str, str]


@final
class MTLSValidator:
    """Validates mTLS certificates with chain of trust verification"""

    __slots__ = ("_ca_bundle", "_ca_certificates", "_ocsp_enabled")

    _CA_CACHE: ClassVar[dict[bytes, list[Certificate]]] = {}
    DEFAULT_HASH_ALGORITHM: Final = hashes.SHA256()

    def __init__(
        self,
        ca_bundle: bytes | str | Path,
        *,
        ocsp_enabled: bool = True,
    ) -> None:
        """Initialize validator with CA bundle and OCSP settings

        Args:
            ca_bundle: PEM-encoded CA certificates or path to file
            ocsp_enabled: Whether to perform OCSP revocation checks
        """
        self._ca_bundle = ca_bundle
        self._ocsp_enabled = ocsp_enabled
        self._ca_certificates = self._load_ca_bundle()

    def _load_ca_bundle(self) -> list[Certificate]:
        """Load and cache CA certificates from bundle"""
        if isinstance(self._ca_bundle, (str, Path)):
            path = Path(self._ca_bundle)
            with path.open("rb") as f:
                data = f.read()
        else:
            data = self._ca_bundle

        if data in self._CA_CACHE:
            return self._CA_CACHE[data]

        certs: list[Certificate] = load_pem_x509_certificates(data)
        self._CA_CACHE[data] = certs
        return certs

    def extract_certificate_info(self, cert: ssl.SSLObject) -> CertificateInfo:
        """Extract structured information from peer certificate

        Raises:
            ValueError: If certificate parsing fails
        """
        if not cert:
            msg = "No certificate provided"
            raise ValueError(msg)

        der_cert = cert.getpeercert(binary_form=True)
        if not der_cert:
            msg = "Empty certificate data"
            raise ValueError(msg)

        try:
            x509_cert = x509.load_der_x509_certificate(der_cert, default_backend())

            def parse_name(name: x509.Name) -> dict[str, str]:
                return {
                    attr.rfc4514_string().split("=")[0]: attr.value  # type: ignore[reportUnknownMemberType]
                    for attr in name  # type: ignore[reportUnknownMemberType]
                }

            extensions = {}
            for ext in x509_cert.extensions:
                try:
                    extensions[str(ext.oid)] = str(ext.value)
                except (AttributeError, TypeError):
                    extensions[str(ext.oid)] = "UNPARSABLE_EXTENSION"

            return {
                "subject": parse_name(x509_cert.subject),
                "issuer": parse_name(x509_cert.issuer),
                "serial": x509_cert.serial_number,
                "fingerprint": x509_cert.fingerprint(self.DEFAULT_HASH_ALGORITHM).hex(),
                "not_before": x509_cert.not_valid_before.replace(
                    tzinfo=UTC,
                ).timestamp(),
                "not_after": x509_cert.not_valid_after.replace(tzinfo=UTC).timestamp(),
                "extensions": extensions,
            }
        except Exception as e:
            msg = f"Certificate parsing failed: {e}"
            raise ValueError(msg) from e

    def verify_certificate(
        self,
        cert: ssl.SSLObject,
        expected_fingerprint: str | None = None,
        *,
        check_ocsp: bool | None = None,
    ) -> bool:
        """Perform full certificate validation

        Args:
            cert: SSL peer certificate
            expected_fingerprint: Expected SHA-256 fingerprint (optional)
            check_ocsp: Override default OCSP checking behavior

        Returns:
            bool: True if certificate is valid

        Raises:
            ValueError: If validation fails critically
        """
        if not cert:
            return False

        try:
            der_cert = cert.getpeercert(binary_form=True)
            if not der_cert:
                return False

            x509_cert = x509.load_der_x509_certificate(der_cert, default_backend())

            if expected_fingerprint:
                actual_fp = x509_cert.fingerprint(self.DEFAULT_HASH_ALGORITHM).hex()
                if not secrets.compare_digest(
                    actual_fp.lower(),
                    expected_fingerprint.lower(),
                ):
                    return False

            # Validity period check
            now = datetime.now(UTC)
            valid_from = x509_cert.not_valid_before.replace(tzinfo=UTC)
            valid_to = x509_cert.not_valid_after.replace(tzinfo=UTC)
            if not (valid_from <= now <= valid_to):
                return False

            # Chain of trust verification
            if not self._verify_chain_of_trust(x509_cert):
                return False

            # OCSP revocation check
            ocsp_check = check_ocsp if check_ocsp is not None else self._ocsp_enabled
            return not (ocsp_check and not self._check_ocsp_revocation(x509_cert))
        except Exception as e:
            msg = f"Certificate validation failed: {e}"
            raise ValueError(msg) from e

    def _verify_chain_of_trust(self, cert: Certificate) -> bool:
        """Verify certificate against CA bundle"""
        msg = "Chain of trust verification not implemented"
        raise NotImplementedError(msg)

    def _check_ocsp_revocation(self, cert: Certificate) -> bool:
        """Check certificate revocation status via OCSP"""
        msg = "OCSP verification not implemented"
        raise NotImplementedError(msg)

    def _find_issuer_certificate(self, cert: Certificate) -> Certificate:
        """Find issuing CA certificate from bundle"""
        issuer_dn = cert.issuer.rfc4514_string()
        for ca_cert in self._ca_certificates:
            if ca_cert.subject.rfc4514_string() == issuer_dn:
                return ca_cert
        msg = "Issuer certificate not found in CA bundle"
        raise ValueError(msg)
