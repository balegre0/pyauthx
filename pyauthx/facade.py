from __future__ import annotations

from typing import TYPE_CHECKING, Literal, final

from pyauthx.core.key_management import Jwk, KeyManager
from pyauthx.services.auth_service import AuthService
from pyauthx.utils.mtls import MTLSValidator

if TYPE_CHECKING:
    import ssl
    from datetime import datetime

    from pyauthx.models.tokens import ClientId, UserId


@final
class PyAuthX:
    """Main client interface for authentication operations."""

    __slots__ = (
        "_access_token_ttl",
        "_auth_service",
        "_key_manager",
        "_mtls_validator",
        "_refresh_token_ttl",
    )

    def __init__(
        self,
        algorithm: Literal["HS256", "RS256", "ES256"] = "RS256",
        key_size: int = 2048,
        access_token_ttl: int = AuthService.DEFAULT_ACCESS_TOKEN_TTL,
        refresh_token_ttl: int = AuthService.DEFAULT_REFRESH_TOKEN_TTL,
        ca_bundle: str | None = None,
    ) -> None:
        """Initialize authentication service with cryptographic settings."""
        self._key_manager = KeyManager(algorithm, key_size)
        self._auth_service = AuthService(
            self._key_manager,
            access_token_ttl,
            refresh_token_ttl,
        )
        self._mtls_validator = MTLSValidator(ca_bundle) if ca_bundle else None
        self._access_token_ttl = access_token_ttl
        self._refresh_token_ttl = refresh_token_ttl

    def issue_tokens(
        self,
        user_id: UserId,
        client_id: ClientId | None = None,
        mtls_cert: ssl.SSLObject | None = None,
    ) -> tuple[str, str, datetime]:
        """Issue new access and refresh tokens with optional mTLS binding."""
        mtls_thumbprint = None
        if (
            mtls_cert
            and self._mtls_validator
            and (cert_info := self._mtls_validator.extract_certificate_info(mtls_cert))
        ):
            mtls_thumbprint = cert_info["fingerprint"]

        access_token = self._auth_service.create_token(user_id)
        refresh_token, expires_at = self._auth_service.create_refresh_token(
            user_id,
            client_id,
            mtls_thumbprint,
        )
        return access_token, refresh_token, expires_at

    def verify_token(
        self,
        token: str,
        audience: ClientId | None = None,
    ) -> dict[str, object]:
        """Verify and decode a token, returning its claims."""
        return self._auth_service.verify_token(token, audience).model_dump()

    def refresh_tokens(
        self,
        refresh_token: str,
        mtls_cert: ssl.SSLObject | None = None,
    ) -> tuple[str, str]:
        """Refresh an access token using a valid refresh token."""
        mtls_thumbprint = None
        if (
            mtls_cert
            and self._mtls_validator
            and (cert_info := self._mtls_validator.extract_certificate_info(mtls_cert))
        ):
            mtls_thumbprint = cert_info["fingerprint"]

        return self._auth_service.refresh_tokens(refresh_token, mtls_thumbprint)

    def rotate_keys(self) -> None:
        """Rotate the cryptographic keys used for token signing."""
        self._key_manager.rotate_key()

    def get_jwks(self) -> list[Jwk]:
        """Retrieve the JSON Web Key Set (JWKS) for public key verification."""
        return self._key_manager.get_jwks()

    @property
    def key_manager(self) -> KeyManager:
        """Provides access to the underlying key management service."""
        return self._key_manager

    @property
    def auth_service(self) -> AuthService:
        """Provides access to the core authentication service."""
        return self._auth_service
