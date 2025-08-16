from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Annotated, Final
from uuid import UUID, uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    conbytes,
    constr,
    field_serializer,
    field_validator,
)

SHA256_HASH_LENGTH: Final[int] = 32  # SHA-256 produces 32-byte hashes
MAX_FUTURE_TIMESTAMP_OFFSET: Final[int] = 31536000  # 1 year in seconds

SHA256Hash = Annotated[bytes, conbytes(min_length=32, max_length=32)]
UserId = Annotated[
    str,
    constr(min_length=8, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$"),
]
ClientId = Annotated[
    str,
    constr(min_length=3, max_length=32, pattern=r"^[a-zA-Z0-9_]+$"),
]
Thumbprint = Annotated[
    str,
    constr(min_length=64, max_length=64, pattern=r"^[a-f0-9]{64}$"),
]


class TokenPayload(BaseModel):
    """JWT payload structure with standard claims and validation.

    Attributes:
        sub: Subject identifier (user ID)
        exp: Expiration timestamp (seconds since epoch)
        iat: Issued at timestamp (auto-generated if not provided)
        jti: Unique token identifier (auto-generated UUID)
        aud: Intended audience (client ID)
        iss: Token issuer
        scope: Authorization scope
        azp: Authorized party (client ID)
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
        str_min_length=1,
    )

    sub: UserId = Field(..., description="Subject identifier (user ID)")
    exp: float = Field(..., description="Expiration timestamp (seconds since epoch)")
    iat: float = Field(
        default_factory=lambda: datetime.now(UTC).timestamp(),
        description="Issued at timestamp",
    )
    jti: UUID = Field(
        default_factory=uuid4,
        description="Unique token identifier (JWT ID)",
    )
    aud: ClientId | None = Field(
        default=None,
        description="Intended audience (client ID)",
    )
    iss: str | None = Field(
        default=None,
        min_length=3,
        max_length=256,
        description="Token issuer",
    )
    scope: str | None = Field(
        default=None,
        min_length=3,
        max_length=256,
        description="Authorization scope",
    )
    azp: ClientId | None = Field(
        default=None,
        description="Authorized party (client ID)",
    )

    @field_validator("exp", "iat")
    @classmethod
    def validate_timestamps(cls, timestamp: float) -> float:
        """Ensure timestamps are within valid ranges."""
        current_time = datetime.now(UTC).timestamp()
        if timestamp < 0:
            msg = "Timestamp must be positive"
            raise ValueError(msg)
        if timestamp > current_time + MAX_FUTURE_TIMESTAMP_OFFSET:
            msg = "Timestamp too far in the future (max 1 year)"
            raise ValueError(msg)
        return timestamp

    @field_validator("sub", "azp", "aud")
    @classmethod
    def validate_identifiers(cls, value: str | None) -> str | None:
        """Validate identifier strings don't contain special characters."""
        if value and any(char in value for char in "!@#$%^&*()+={}[]|\\:;\"'<>,?/"):
            msg = "Identifiers cannot contain special characters"
            raise ValueError(msg)
        return value

    @field_serializer("jti")
    def serialize_jti(self, jti: UUID) -> str:
        """Convert UUID to str"""
        return str(jti)


class RefreshTokenRecord(BaseModel):
    """Secure storage record for refresh tokens with mTLS support."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
    )

    token_hash: SHA256Hash = Field(..., description="SHA-256 hash of the raw token")
    user_id: UserId = Field(..., description="Associated user identifier")
    expires_at: datetime = Field(..., description="Expiration datetime in UTC")
    used: bool = Field(
        default=False,
        description="Indicates if token has been consumed",
    )
    client_id: ClientId | None = Field(
        default=None,
        description="Authorized client identifier",
    )
    mtls_cert_thumbprint: Thumbprint | None = Field(
        default=None,
        description="SHA-256 fingerprint of bound mTLS certificate",
    )
    token_family: UUID = Field(
        default_factory=uuid4,
        description="Token family identifier for rotation",
    )

    @field_validator("expires_at")
    @classmethod
    def ensure_utc(cls, dt: datetime) -> datetime:
        """Ensure datetime is timezone-aware and converted to UTC."""
        if dt.tzinfo is None:
            msg = "Datetime must have timezone specified"
            raise ValueError(msg)
        return dt.astimezone(UTC) if dt.tzinfo != UTC else dt

    @field_validator("token_hash")
    @classmethod
    def validate_hash_length(cls, hash_bytes: bytes) -> bytes:
        """Validate SHA-256 hash length."""
        if len(hash_bytes) != SHA256_HASH_LENGTH:
            msg = f"Hash must be exactly {SHA256_HASH_LENGTH} bytes (SHA-256)"
            raise ValueError(msg)
        return hash_bytes

    @classmethod
    def create(
        cls,
        raw_token: str,
        user_id: str,
        expires_at: datetime,
        client_id: str | None = None,
        mtls_cert: bytes | None = None,
    ) -> RefreshTokenRecord:
        """Factory method for creating new refresh token records."""
        token_hash = hashlib.sha256(raw_token.encode()).digest()
        thumbprint = hashlib.sha256(mtls_cert).hexdigest() if mtls_cert else None

        expires_at_utc = (
            expires_at.astimezone(UTC)
            if expires_at.tzinfo
            else expires_at.replace(tzinfo=UTC)
        )

        return cls(
            token_hash=token_hash,
            user_id=user_id,
            expires_at=expires_at_utc,
            client_id=client_id,
            mtls_cert_thumbprint=thumbprint,
        )
