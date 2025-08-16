import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from typing import NoReturn, overload
from uuid import UUID

import jwt
from cryptography.fernet import InvalidToken
from jwt import PyJWTError
from pydantic import ValidationError

from pyauthx.core.key_management import KeyManager
from pyauthx.exceptions import (
    InvalidTokenError,
    SecurityError,
    TokenExpiredError,
    TokenReuseError,
    mTLSValidationError,
)
from pyauthx.models.tokens import ClientId, RefreshTokenRecord, TokenPayload, UserId


class AuthService:
    __slots__ = (
        "_access_token_ttl",
        "_algorithm",
        "_key_manager",
        "_refresh_store",
        "_refresh_token_ttl",
    )

    DEFAULT_ACCESS_TOKEN_TTL: int = 900  # 15m
    DEFAULT_REFRESH_TOKEN_TTL: int = 2592000  # 30d

    def __init__(
        self,
        key_manager: KeyManager,
        access_token_ttl: int = DEFAULT_ACCESS_TOKEN_TTL,
        refresh_token_ttl: int = DEFAULT_REFRESH_TOKEN_TTL,
    ) -> None:
        self._key_manager = key_manager
        self._refresh_store: dict[str, RefreshTokenRecord] = {}
        self._access_token_ttl = access_token_ttl
        self._refresh_token_ttl = refresh_token_ttl
        self._algorithm = key_manager.algorithm

    def _handle_error(
        self,
        msg: str,
        exception_type: type[Exception] = SecurityError,
        original_exception: Exception | None = None,
    ) -> NoReturn:
        raise exception_type(msg) from original_exception

    @overload
    def create_token(self, subject: UserId) -> str: ...

    @overload
    def create_token(self, subject: UserId, audience: ClientId) -> str: ...

    @overload
    def create_token(self, subject: UserId, audience: ClientId, issuer: str) -> str: ...

    def create_token(
        self,
        subject: UserId,
        audience: ClientId | None = None,
        issuer: str | None = None,
    ) -> str | None:
        try:
            payload = TokenPayload(
                sub=subject,
                exp=(
                    datetime.now(UTC) + timedelta(seconds=self._access_token_ttl)
                ).timestamp(),
                aud=audience,
                iss=issuer,
            ).model_dump()

            return jwt.encode(
                payload,
                self._key_manager.get_signing_key(),
                algorithm=self._algorithm,
                headers={"kid": self._key_manager.current_key},
            )
        except (PyJWTError, ValidationError, ValueError, TypeError) as e:
            self._handle_error("Error al crear el token", SecurityError, e)

    def create_refresh_token(
        self,
        user_id: UserId,
        client_id: ClientId | None = None,
        mtls_thumbprint: str | None = None,
    ) -> tuple[str, datetime] | None:
        try:
            raw_token = secrets.token_urlsafe(64)
            token_hash = hashlib.sha256(raw_token.encode()).digest()
            expires_at = datetime.now(UTC) + timedelta(seconds=self._refresh_token_ttl)

            record = RefreshTokenRecord(
                token_hash=token_hash,
                user_id=user_id,
                expires_at=expires_at,
                client_id=client_id,
                mtls_cert_thumbprint=mtls_thumbprint,
            )

            self._refresh_store[record.token_family.hex] = record
        except (InvalidToken, ValueError, TypeError, ValidationError) as e:
            self._handle_error("Error al crear el refresh token", SecurityError, e)
        else:
            return raw_token, expires_at

    def verify_token(
        self,
        token: str,
        audience: ClientId | None = None,
        require_issuer: str | None = None,
    ) -> TokenPayload:
        try:
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")
            key = self._key_manager.get_verification_key(kid) if kid else None

            if not key:
                self._handle_error("Key ID invalido", InvalidTokenError)

            payload = jwt.decode(
                token,
                key,
                algorithms=[self._algorithm],
                audience=audience,
                issuer=require_issuer,
                options={
                    "require_exp": True,
                    "require_iat": True,
                    "verify_aud": bool(audience),
                    "verify_iss": bool(require_issuer),
                },
            )
            return TokenPayload(**payload)
        except jwt.ExpiredSignatureError as e:
            self._handle_error("Token expirado", TokenExpiredError, e)
        except jwt.InvalidTokenError as e:
            self._handle_error("Token invalido", InvalidTokenError, e)
        except (PyJWTError, ValidationError, ValueError, TypeError) as e:
            self._handle_error("Token verificacion fallida", SecurityError, e)

    def refresh_tokens(
        self,
        refresh_token: str,
        mtls_thumbprint: str | None = None,
    ) -> tuple[str, str] | None:
        try:
            token_hash = hashlib.sha256(refresh_token.encode()).digest()
            record = next(
                (r for r in self._refresh_store.values() if r.token_hash == token_hash),
                None,
            )

            if not record:
                self._handle_error("Refresh token invalido", InvalidTokenError)

            if record.used:
                self._revoke_token_family(record.token_family)
                self._handle_error(
                    "Refresh token re-usado detectado",
                    TokenReuseError,
                )

            self._validate_mtls(record, mtls_thumbprint)
            self._validate_token_expiry(record)

            record.used = True
            new_access_token = self.create_token(record.user_id)
            refresh_result = self.create_refresh_token(
                record.user_id,
                record.client_id,
                record.mtls_cert_thumbprint,
            )

            if refresh_result is None:
                self._handle_error("No se pudo crear el refresh token", SecurityError)

            new_refresh_token, _ = refresh_result
        except SecurityError:
            raise
        except (ValueError, TypeError, PyJWTError, ValidationError) as e:
            self._handle_error("Token refresh failed", SecurityError, e)
        else:
            return new_access_token, new_refresh_token

    def revoke_token(self, token_hash: str) -> None:
        if token_hash in self._refresh_store:
            del self._refresh_store[token_hash]

    def cleanup_expired_tokens(self) -> None:
        now = datetime.now(UTC)
        self._refresh_store = {
            k: v for k, v in self._refresh_store.items() if v.expires_at > now
        }

    def is_token_active(self, token_hash: str) -> bool:
        record = self._refresh_store.get(token_hash)
        return (
            record is not None
            and not record.used
            and datetime.now(UTC) <= record.expires_at
        )

    def _validate_mtls(
        self,
        record: RefreshTokenRecord,
        mtls_thumbprint: str | None,
    ) -> None:
        if record.mtls_cert_thumbprint:
            if not mtls_thumbprint:
                self._handle_error("Client certificado necesario", mTLSValidationError)
            if record.mtls_cert_thumbprint != mtls_thumbprint:
                self._handle_error("El certificado no coincide", mTLSValidationError)

    def _validate_token_expiry(self, record: RefreshTokenRecord) -> None:
        if datetime.now(UTC) > record.expires_at:
            self._handle_error("Refresh token expirado", TokenExpiredError)

    def _revoke_token_family(self, family_id: UUID) -> None:
        family_key = family_id.hex
        if family_key in self._refresh_store:
            del self._refresh_store[family_key]

        self._refresh_store = {
            k: v for k, v in self._refresh_store.items() if v.token_family != family_id
        }
