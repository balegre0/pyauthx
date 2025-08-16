import ssl
from datetime import UTC, datetime
from pathlib import Path
from typing import ClassVar, TypedDict, final

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
    __slots__ = ("_ca_bundle", "_ca_certificates", "_ocsp_enabled")

    _CA_CACHE: ClassVar[dict[bytes, list[Certificate]]] = {}

    def __init__(self, ca_bundle: bytes | str, *, ocsp_enabled: bool = True) -> None:
        self._ca_bundle = ca_bundle
        self._ocsp_enabled = ocsp_enabled
        self._ca_certificates = self._load_ca_bundle()

    def _load_ca_bundle(self) -> list[Certificate]:
        if isinstance(self._ca_bundle, str):
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

    def extract_cert_info(self, cert: ssl.SSLObject) -> CertificateInfo | None:
        if not cert:
            return None

        try:
            der_cert = cert.getpeercert(binary_form=True)
            if not der_cert:
                return None

            x509_cert = x509.load_der_x509_certificate(der_cert, default_backend())
            subject: dict[str, str] = {
                attr.rfc4514_string().split("=")[0]: attr.value
                for attr in x509_cert.subject
            }

            issuer: dict[str, str] = {
                attr.rfc4514_string().split("=")[0]: attr.value
                for attr in x509_cert.issuer
            }

            extensions: dict[str, str] = {}
            for ext in x509_cert.extensions:
                try:
                    extensions[str(ext.oid.dotted_string)] = str(ext.value)
                except (AttributeError, TypeError):
                    extensions[str(ext.oid.dotted_string)] = "UNPARSABLE_EXTENSION"

            return {
                "subject": subject,
                "issuer": issuer,
                "serial": x509_cert.serial_number,
                "fingerprint": x509_cert.fingerprint(hashes.SHA256()).hex(),
                "not_before": x509_cert.not_valid_before.replace(
                    tzinfo=UTC,
                ).timestamp(),
                "not_after": x509_cert.not_valid_after.replace(
                    tzinfo=UTC,
                ).timestamp(),
                "extensions": extensions,
            }
        except Exception as e:
            msg = f"Error extrayendo info certificado: {e!s}"
            raise ValueError(msg) from e

    def verify_certificate(
        self,
        cert: ssl.SSLObject,
        expected_fingerprint: str | None = None,
        *,
        check_ocsp: bool | None = None,
    ) -> bool:
        if not cert:
            return False

        try:
            der_cert = cert.getpeercert(binary_form=True)
            if not der_cert:
                return False

            x509_cert = x509.load_der_x509_certificate(der_cert, default_backend())

            if expected_fingerprint is not None:
                actual_fp = x509_cert.fingerprint(hashes.SHA256()).hex()
                if actual_fp.lower() != expected_fingerprint.lower():
                    return False

            now = datetime.now(UTC)
            not_before = x509_cert.not_valid_before.replace(tzinfo=UTC)
            not_after = x509_cert.not_valid_after.replace(tzinfo=UTC)
            if not (not_before <= now <= not_after):
                return False

            if not self._verify_chain_of_trust(x509_cert):
                return False

            ocsp_check = check_ocsp if check_ocsp is not None else self._ocsp_enabled
            return not (ocsp_check and not self._check_ocsp_revocation(x509_cert))

        except (ValueError, x509.ExtensionNotFound) as e:
            msg = f"Fallo en verificación de certificado: {e!s}"
            raise ValueError(msg) from e

    def _verify_chain_of_trust(self, cert: Certificate) -> bool: ...

    def _check_ocsp_revocation(self, cert: Certificate) -> bool: ...

    def _find_issuer(self, cert: Certificate) -> Certificate:
        issuer_dn = cert.issuer.rfc4514_string()
        for ca_cert in self._ca_certificates:
            if ca_cert.subject.rfc4514_string() == issuer_dn:
                return ca_cert
        msg = "Certificado de emisor no encontrado en el paquete de CA"
        raise ValueError(msg)
