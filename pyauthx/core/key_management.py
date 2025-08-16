from __future__ import annotations

import secrets
from collections import deque
from datetime import UTC, datetime, timedelta
from typing import (
    TYPE_CHECKING,
    Final,
    Literal,
    NoReturn,
    NotRequired,
    TypedDict,
    final,
)

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
)

from pyauthx.exceptions import SecurityError

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes


class Jwk(TypedDict):
    """JSON Web Key (JWK) representation for cryptographic keys."""

    kty: Literal["RSA", "EC"]
    kid: str
    use: Literal["sig", "enc"]
    alg: str
    n: NotRequired[str]
    e: NotRequired[str]
    crv: NotRequired[str]
    x: NotRequired[str]
    y: NotRequired[str]


@final
class KeyManager:
    """Manages crypto keys for token signing & verification with automatic rotation."""

    __slots__ = (
        "_algorithm",
        "_current_key",
        "_key_size",
        "_key_store",
        "_last_rotation",
        "_previous_keys",
        "_rotation_period",
    )

    KEY_ROTATION_PERIOD: Final[timedelta] = timedelta(days=1)
    MAX_PREVIOUS_KEYS: Final[int] = 3

    def __init__(
        self,
        algorithm: Literal["HS256", "RS256", "ES256"],
        key_size: int = 2048,
    ) -> None:
        """Initialize the key manager with cryptographic settings."""
        self._algorithm = algorithm
        self._key_size = key_size
        self._key_store: dict[str, bytes] = {}
        self._previous_keys: deque[tuple[datetime, str]] = deque(
            maxlen=self.MAX_PREVIOUS_KEYS,
        )
        self._rotation_period = self.KEY_ROTATION_PERIOD
        self._last_rotation = datetime.now(UTC)
        self._generate_new_key()

    def _generate_new_key(self) -> None:
        """Generate a new cryptographic key and make it current."""
        key_id = secrets.token_urlsafe(8)

        if self._algorithm.startswith("HS"):
            key = secrets.token_bytes(self._key_size // 8)
        elif self._algorithm == "RS256":
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=self._key_size,
                backend=default_backend(),
            )
            key = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        elif self._algorithm == "ES256":
            private_key = ec.generate_private_key(
                ec.SECP256R1(),
                default_backend(),
            )
            key = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        else:
            msg = f"Unsupported algorithm: {self._algorithm}"
            raise ValueError(msg)

        self._key_store[key_id] = key
        self._current_key = key_id
        self._last_rotation = datetime.now(UTC)

    def rotate_key(self) -> None:
        """Rotate the current signing key and maintain key history."""
        self._previous_keys.append((datetime.now(UTC), self._current_key))
        self._generate_new_key()

        expire_time = datetime.now(UTC) - (
            self._rotation_period * self.MAX_PREVIOUS_KEYS
        )
        while self._previous_keys and self._previous_keys[0][0] < expire_time:
            _, old_key_id = self._previous_keys.popleft()
            self._key_store.pop(old_key_id, None)

    def get_jwks(self) -> list[Jwk]:
        """Get JSON Web Key Set (JWKS) containing current public key metadata."""
        return [
            {
                "kty": "RSA" if self._algorithm == "RS256" else "EC",
                "kid": self._current_key,
                "use": "sig",
                "alg": self._algorithm,
            },
        ]

    def get_signing_key(self) -> bytes:
        """Get the current private key for signing operations."""
        return self._key_store[self._current_key]

    @staticmethod
    def _public_bytes_from_rsa(private_key: rsa.RSAPrivateKey) -> bytes:
        public_key = private_key.public_key()
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @staticmethod
    def _public_bytes_from_ec(private_key: ec.EllipticCurvePrivateKey) -> bytes:
        public_key = private_key.public_key()
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @staticmethod
    def _rethrow(msg: str, err: Exception) -> NoReturn:
        raise SecurityError(msg) from err

    def _load_private_key(self, pem: bytes) -> PrivateKeyTypes:
        try:
            return load_pem_private_key(pem, password=None, backend=default_backend())
        except (ValueError, TypeError, UnsupportedAlgorithm) as e:
            self._rethrow(f"Failed to load verification key: {e!s}", e)

    def _to_verification_bytes(
        self,
        loaded: PrivateKeyTypes,
    ) -> bytes:
        if self._algorithm == "RS256":
            if not isinstance(loaded, rsa.RSAPrivateKey):
                msg = "Loaded key is not an RSA private key"
                raise SecurityError(msg)
            return self._public_bytes_from_rsa(loaded)

        if self._algorithm == "ES256":
            if not isinstance(loaded, ec.EllipticCurvePrivateKey):
                msg = "Loaded key is not an EC private key"
                raise SecurityError(msg)
            return self._public_bytes_from_ec(loaded)

        msg = f"Unsupported algorithm: {self._algorithm}"
        raise ValueError(msg)

    def get_verification_key(self, kid: str) -> bytes | None:
        """Get the appropriate verification key for the given key id."""
        private_key_pem = self._key_store.get(kid)
        if not private_key_pem:
            return None

        # HMAC reuses the same symmetric key
        if self._algorithm.startswith("HS"):
            return private_key_pem

        loaded = self._load_private_key(private_key_pem)
        return self._to_verification_bytes(loaded)

    @property
    def algorithm(self) -> str:
        """Get the configured JWT signing algorithm."""
        return self._algorithm

    @property
    def current_key(self) -> str:
        """Get the identifier of the current signing key."""
        return self._current_key
