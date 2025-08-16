import hashlib
from datetime import UTC, datetime
from typing import Annotated, Final
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, conbytes, constr, field_validator

SHA256_HASH_LENGTH: Final[int] = 32
MAX_FUTURE_TIMESTAMP_OFFSET: Final[int] = 31536000

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
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
        str_min_length=1,
    )

    sub: UserId
    exp: float
    iat: float = Field(default_factory=lambda: datetime.now(UTC).timestamp())
    jti: UUID = Field(default_factory=uuid4, description="Unique token identifier")
    aud: ClientId | None = Field(default=None, description="Audience (client ID)")
    iss: str | None = Field(
        default=None,
        min_length=3,
        max_length=256,
        description="Issuer",
    )
    scope: str | None = Field(
        default=None,
        min_length=3,
        max_length=256,
        description="Authorization scope",
    )
    azp: ClientId | None = Field(
        default=None,
        description="Authorization party (client ID)",
    )

    @field_validator("exp", "iat")
    @classmethod
    def validate_timestamps(cls, v: float) -> float:
        current_time = datetime.now(UTC).timestamp()
        if v < 0:
            msg = "El timestamp debe ser positivo"
            raise ValueError(msg)
        if v > current_time + MAX_FUTURE_TIMESTAMP_OFFSET:  # 1y
            msg = "Timestamp demasiado lejano (futuro)"
            raise ValueError(msg)
        return v

    @field_validator("sub", "azp", "aud")
    @classmethod
    def validate_identifiers(cls, v: str | None) -> str | None:
        if v and any(char in v for char in "!@#$%^&*()+={}[]|\\:;\"'<>,?/"):
            msg = "Caracteres no permitidos en identificadores"
            raise ValueError(msg)
        return v


class RefreshTokenRecord(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
    )

    token_hash: SHA256Hash = Field(description="Secure hash for token (SHA-256)")
    user_id: UserId = Field(description="Associated user ID")
    expires_at: datetime = Field(description="Expiration date/time in UTC")
    used: bool = Field(
        default=False,
        description="Indicates if the token has been used",
    )
    client_id: ClientId | None = Field(
        default=None,
        description="Authorized Customer ID",
    )
    mtls_cert_thumbprint: Thumbprint | None = Field(
        default=None,
        description="SHA-256 fingerprint of the mTLS certificate",
    )
    token_family: UUID = Field(
        default_factory=uuid4,
        description="Unique identifier of the token family",
    )

    @field_validator("expires_at")
    @classmethod
    def ensure_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            msg = "La fecha debe tener zona horaria especificada"
            raise ValueError(msg)
        if v.tzinfo != UTC:
            return v.astimezone(UTC)
        return v

    @field_validator("token_hash")
    @classmethod
    def validate_hash_length(cls, v: bytes) -> bytes:
        if len(v) != SHA256_HASH_LENGTH:
            msg = f"El hash debe tener exactamente {SHA256_HASH_LENGTH} bytes"
            raise ValueError(msg)
        return v

    @classmethod
    def create(
        cls,
        raw_token: str,
        user_id: str,
        expires_at: datetime,
        client_id: str | None = None,
        mtls_cert: bytes | None = None,
    ) -> "RefreshTokenRecord":
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
