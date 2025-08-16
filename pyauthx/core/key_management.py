import secrets
from collections import deque
from datetime import UTC, datetime, timedelta
from typing import Final, Literal, NotRequired, TypedDict, final

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa


class Jwk(TypedDict):
    """JSON Web Key (JWK) representation for cryptographic keys.

    Attributes:
        kty: Key type (RSA or EC)
        kid: Key identifier
        use: Intended use (sig for signature)
        alg: Algorithm identifier
        n: RSA modulus (required for RSA)
        e: RSA public exponent (required for RSA)
        crv: EC curve name (required for EC)
        x: EC x-coordinate (required for EC)
        y: EC y-coordinate (required for EC)
    """

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
        """Generate a new cryptographic key and make it current.

        Creates appropriate key material based on configured algorithm:
        - HS256: Symmetric HMAC key
        - RS256: RSA key pair
        - ES256: ECDSA key pair (P-256 curve)
        """
        key_id = secrets.token_urlsafe(8)  # Cryptographically secure key ID

        if self._algorithm.startswith("HS"):
            # Generate symmetric key for HMAC
            key = secrets.token_bytes(self._key_size // 8)
        elif self._algorithm == "RS256":
            # Generate RSA key pair
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
            # Generate ECDSA key pair (P-256 curve)
            private_key = ec.generate_private_key(
                ec.SECP256R1(),  # NIST P-256 curve
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
        # Archive current key
        self._previous_keys.append(
            (datetime.now(UTC), self._current_key),
        )

        # Generate new key
        self._generate_new_key()

        # Clean up expired keys
        expire_time = datetime.now(UTC) - (
            self._rotation_period * self.MAX_PREVIOUS_KEYS
        )
        while self._previous_keys and self._previous_keys[0][0] < expire_time:
            _, old_key_id = self._previous_keys.popleft()
            self._key_store.pop(old_key_id, None)

    def get_jwks(self) -> list[Jwk]:
        """Get JSON Web Key Set (JWKS) containing current public key."""
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

    def get_verification_key(self, kid: str) -> bytes | None:
        """Get a specific key for verification by key ID."""
        return self._key_store.get(kid)

    @property
    def algorithm(self) -> str:
        """Get the configured JWT signing algorithm."""
        return self._algorithm

    @property
    def current_key(self) -> str:
        """Get the identifier of the current signing key."""
        return self._current_key
