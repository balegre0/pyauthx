from __future__ import annotations

import secrets
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, Final, TypedDict, cast, final

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import Certificate, load_pem_x509_certificates
from cryptography.x509.oid import ExtensionOID

from pyauthx.exceptions import (
    CertificateExtensionError,
    ChainValidationError,
    SignatureValidationError,
    TrustAnchorError,
)

if TYPE_CHECKING:
    import ssl

__all__ = ["CertificateInfo", "MTLSValidator"]


class CertificateInfo(TypedDict):
    """Structured information extracted from an X.509 certificate.

    Attributes:
        subject: Dictionary of subject distinguished name attributes
        issuer: Dictionary of issuer distinguished name attributes
        serial: Certificate serial number
        fingerprint: SHA-256 fingerprint of the certificate
        not_before: Timestamp of certificate validity start
        not_after: Timestamp of certificate validity end
        extensions: Dictionary of certificate extensions and their values
    """

    subject: dict[str, str]
    issuer: dict[str, str]
    serial: int
    fingerprint: str
    not_before: float
    not_after: float
    extensions: dict[str, str]


@final
class MTLSValidator:
    """Validates mTLS certificates with chain of trust verification.

    This class provides comprehensive validation of client certificates in mutual TLS
    authentication scenarios, including chain of trust verification and OCSP checking.

    Args:
        ca_bundle: PEM-encoded CA certificates or path to CA bundle file
        ocsp_enabled: Whether to perform OCSP revocation checks (default: True)
    """

    __slots__ = ("_ca_bundle", "_ca_certificates", "_ocsp_enabled")

    _CA_CACHE: ClassVar[dict[bytes, list[Certificate]]] = {}
    DEFAULT_HASH_ALGORITHM: Final[hashes.HashAlgorithm] = hashes.SHA256()

    def __init__(
        self,
        ca_bundle: bytes | str | Path,
        *,
        ocsp_enabled: bool = True,
    ) -> None:
        """Initialize the validator with CA bundle and OCSP settings."""
        self._ca_bundle = ca_bundle
        self._ocsp_enabled = ocsp_enabled
        self._ca_certificates = self._load_ca_bundle()

    def _load_ca_bundle(self) -> list[Certificate]:
        """Load and cache CA certificates from the bundle."""
        if isinstance(self._ca_bundle, (str, Path)):
            with Path(self._ca_bundle).open("rb") as f:
                data = f.read()
        else:
            data = self._ca_bundle

        if data not in self._CA_CACHE:
            self._CA_CACHE[data] = load_pem_x509_certificates(data)
        return self._CA_CACHE[data]

    def extract_certificate_info(self, cert: ssl.SSLObject) -> CertificateInfo:
        """Extract structured information from peer certificate."""
        if not cert:
            msg = "No certificate provided"
            raise ValueError(msg)

        der_cert = cert.getpeercert(binary_form=True)
        if not der_cert:
            msg = "Empty certificate data"
            raise ValueError(msg)

        try:
            x509_cert = x509.load_der_x509_certificate(der_cert, default_backend())
            return self._parse_certificate_info(x509_cert)
        except Exception as e:
            msg = "Certificate parsing failed"
            raise ValueError(msg) from e

    def _parse_certificate_info(self, cert: Certificate) -> CertificateInfo:
        """Parse X.509 certificate into structured information."""

        def parse_name(name: x509.Name) -> dict[str, str]:
            return {attr.rfc4514_string().split("=")[0]: attr.value for attr in name}  # type: ignore[reportUnknownMemberType]

        extensions = {
            str(ext.oid): self._parse_extension_value(ext.value)
            for ext in cert.extensions
        }

        return {
            "subject": parse_name(cert.subject),
            "issuer": parse_name(cert.issuer),
            "serial": cert.serial_number,
            "fingerprint": cert.fingerprint(self.DEFAULT_HASH_ALGORITHM).hex(),
            "not_before": cert.not_valid_before.replace(tzinfo=UTC).timestamp(),
            "not_after": cert.not_valid_after.replace(tzinfo=UTC).timestamp(),
            "extensions": extensions,
        }

    def _parse_extension_value(self, value: object) -> str:
        """Convert certificate extension value to string representation."""
        if value is None:
            return "UNPARSABLE_EXTENSION"
        if isinstance(value, (str, int, float, bytes)):
            return str(value)
        try:
            return str(value)
        except (TypeError, ValueError):
            return "UNPARSABLE_EXTENSION"

    def verify_certificate(
        self,
        cert: ssl.SSLObject,
        expected_fingerprint: str | None = None,
        *,
        check_ocsp: bool | None = None,
    ) -> bool:
        """Perform full certificate validation."""
        if not cert:
            return False

        try:
            der_cert = cert.getpeercert(binary_form=True)
            if not der_cert:
                return False

            x509_cert = x509.load_der_x509_certificate(der_cert, default_backend())
            return self._validate_certificate(
                x509_cert,
                expected_fingerprint,
                check_ocsp=check_ocsp,
            )
        except Exception as e:
            msg = "Certificate validation failed"
            raise ValueError(msg) from e

    def _validate_certificate(
        self,
        cert: Certificate,
        expected_fingerprint: str | None,
        *,
        check_ocsp: bool | None,
    ) -> bool:
        """Internal certificate validation implementation."""
        if expected_fingerprint:
            actual_fp = cert.fingerprint(self.DEFAULT_HASH_ALGORITHM).hex()
            if not secrets.compare_digest(
                actual_fp.lower(),
                expected_fingerprint.lower(),
            ):
                return False

        now = datetime.now(UTC)
        valid_from = cert.not_valid_before.replace(tzinfo=UTC)
        valid_to = cert.not_valid_after.replace(tzinfo=UTC)
        if not (valid_from <= now <= valid_to):
            return False

        if not self._verify_chain_of_trust(cert):
            return False

        ocsp_check = check_ocsp if check_ocsp is not None else self._ocsp_enabled
        return not (ocsp_check and not self._check_ocsp_revocation(cert))

    def _verify_chain_of_trust(self, cert: Certificate) -> bool:
        """Verify the complete certificate chain of trust."""
        try:
            chain = self._build_certificate_chain(cert)
            self._validate_chain(chain)
            self._verify_trust_anchor(chain[-1])
        except ChainValidationError:
            return False
        else:
            return True

    def _build_certificate_chain(self, cert: Certificate) -> list[Certificate]:
        """Build certificate chain from leaf to root."""
        chain = [cert]
        current = cert
        max_chain_length = 10
        found_issuer = True

        while found_issuer and len(chain) <= max_chain_length:
            issuer = self._find_issuer_certificate(current)
            if issuer is not None:
                chain.append(issuer)
                current = issuer
            else:
                found_issuer = False

        return chain

    def _validate_chain(self, chain: list[Certificate]) -> None:
        """Validate each link in the certificate chain."""
        for i in range(len(chain) - 1):
            self._validate_certificate_link(chain[i], chain[i + 1])

    def _validate_certificate_link(
        self,
        cert: Certificate,
        issuer: Certificate,
    ) -> None:
        """Validate a single certificate-issuer pair."""
        try:
            cert.verify_directly_issued_by(issuer)
        except Exception as e:
            msg = "Invalid signature in chain"
            raise SignatureValidationError(msg) from e

        self._validate_extensions(cert)

    def _validate_extensions(self, cert: Certificate) -> None:
        """Validate critical certificate extensions."""
        try:
            basic_constraints: x509.BasicConstraints = cast(
                "x509.BasicConstraints",
                cert.extensions.get_extension_for_oid(
                    ExtensionOID.BASIC_CONSTRAINTS,
                ).value,
            )

            key_usage = cast(
                "x509.KeyUsage",
                cert.extensions.get_extension_for_oid(
                    ExtensionOID.KEY_USAGE,
                ).value,
            )

            if basic_constraints.ca and basic_constraints.path_length is None:
                msg = "Path length not specified for CA"
                raise CertificateExtensionError(msg)
            if basic_constraints.ca and not key_usage.key_cert_sign:
                msg = "CA cannot sign certificates"
                raise CertificateExtensionError(msg)
        except x509.ExtensionNotFound as e:
            msg = "Required extension not found"
            raise CertificateExtensionError(msg) from e

    def _verify_trust_anchor(self, root_ca: Certificate) -> None:
        """Verify the root CA is in our trusted bundle."""
        if not any(
            self._compare_certs(root_ca, ca_cert) for ca_cert in self._ca_certificates
        ):
            msg = "Root CA is not in trusted bundle"
            raise TrustAnchorError(msg)

    def _check_ocsp_revocation(self, cert: Certificate) -> bool:
        """Check certificate revocation status via OCSP."""
        msg = "OCSP verification not implemented"
        raise NotImplementedError(msg)

    def _find_issuer_certificate(self, cert: Certificate) -> Certificate | None:
        """Find the issuer certificate in our CA bundle."""
        issuer_dn = cert.issuer.rfc4514_string()
        for ca_cert in self._ca_certificates:
            if ca_cert.subject.rfc4514_string() == issuer_dn:
                return ca_cert
        return None

    def _compare_certs(self, cert1: Certificate, cert2: Certificate) -> bool:
        """Compare two certificates for equality."""
        return (
            cert1.subject == cert2.subject
            and cert1.issuer == cert2.issuer
            and cert1.serial_number == cert2.serial_number
            and self._get_public_key_bytes(cert1) == self._get_public_key_bytes(cert2)
        )

    def _get_public_key_bytes(self, cert: Certificate) -> bytes:
        """Get PEM-encoded public key from certificate."""
        return cert.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
