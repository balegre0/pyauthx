import ssl
from datetime import datetime
from typing import Literal, final

from pyauthx.core.key_management import Jwk, KeyManager
from pyauthx.models.tokens import ClientId, UserId
from pyauthx.services.auth_service import AuthService
from pyauthx.utils.mtls import MTLSValidator


@final
class PyAuthX:
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
        mtls_thumbprint: str | None = None
        if mtls_cert and self._mtls_validator:
            cert_info = self._mtls_validator.extract_cert_info(mtls_cert)
            mtls_thumbprint = cert_info["fingerprint"] if cert_info else None

        access_token: str = self._auth_service.create_token(user_id)
        refresh_token_expires: tuple[str, datetime] | None = (
            self._auth_service.create_refresh_token(
                user_id,
                client_id,
                mtls_thumbprint,
            )
        )

        if refresh_token_expires is None:
            msg = "Error al crear el refresh token"
            raise ValueError(msg)

        refresh_token, expires_at = refresh_token_expires
        return access_token, refresh_token, expires_at

    def verify_token(
        self,
        token: str,
        audience: ClientId | None = None,
    ) -> dict[str, object]:
        verified = self._auth_service.verify_token(token, audience)
        return verified.model_dump()

    def refresh_token(
        self,
        refresh_token: str,
        mtls_cert: ssl.SSLObject | None = None,
    ) -> tuple[str, str]:
        mtls_thumbprint: str | None = None
        if mtls_cert and self._mtls_validator:
            cert_info = self._mtls_validator.extract_cert_info(mtls_cert)
            mtls_thumbprint = cert_info["fingerprint"] if cert_info else None

        result: tuple[str, str] | None = self._auth_service.refresh_tokens(
            refresh_token,
            mtls_thumbprint,
        )
        if result is None:
            msg = "Refresh token invalido o expirado"
            raise ValueError(msg)
        return result

    def rotate_keys(self) -> None:
        self._key_manager.rotate_key()

    def get_jwks(self) -> list[Jwk]:
        return self._key_manager.get_jwks()

    @property
    def key_manager(self) -> KeyManager:
        return self._key_manager

    @property
    def auth_service(self) -> AuthService:
        return self._auth_service
