from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, final

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from pyauthx.core.key_wrapper import ECIESKeyWrapper

if TYPE_CHECKING:
    from .protocols import KeyWrapperProtocol

__all__ = [
    "AES256GCM",
    "AES_KEY_SIZE",
    "TAG_NONCE_SIZE",
    "HybridEncryptor",
]

AES_KEY_SIZE: Final[int] = 32
TAG_NONCE_SIZE: Final[int] = 28


@final
@dataclass(frozen=True, slots=True)
class AES256GCM:
    """Authenticated encryption using AES-256 in GCM mode."""

    key: bytes

    def __post_init__(self) -> None:
        """Validate key size during initialization."""
        if len(self.key) != AES_KEY_SIZE:
            msg = f"AES-256 requires {AES_KEY_SIZE}-byte key"
            raise ValueError(msg)

    def encrypt(
        self,
        plaintext: bytes,
        associated_data: bytes | None = None,
    ) -> tuple[bytes, bytes]:
        """Encrypt data with AES-256-GCM."""
        nonce = secrets.token_bytes(12)
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.GCM(nonce),
            backend=default_backend(),
        )

        encryptor = cipher.encryptor()
        if associated_data:
            encryptor.authenticate_additional_data(associated_data)

        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return ciphertext, nonce + encryptor.tag

    def decrypt(
        self,
        ciphertext: bytes,
        nonce_tag: bytes,
        associated_data: bytes | None = None,
    ) -> bytes:
        """Decrypt AES-256-GCM encrypted data."""
        if len(nonce_tag) != TAG_NONCE_SIZE:
            msg = "Invalid nonce+tag length"
            raise ValueError(msg)

        nonce, tag = nonce_tag[:12], nonce_tag[12:]
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.GCM(nonce, tag),
            backend=default_backend(),
        )
        decryptor = cipher.decryptor()

        if associated_data:
            decryptor.authenticate_additional_data(associated_data)

        return decryptor.update(ciphertext) + decryptor.finalize()


@final
class HybridEncryptor:
    """Combines asymmetric key wrapping with symmetric AES-256-GCM encryption."""

    __slots__ = ("_key_wrapper",)

    def __init__(self, key_wrapper: KeyWrapperProtocol | None = None) -> None:
        """Initialize the hybrid encryptor."""
        self._key_wrapper = key_wrapper or ECIESKeyWrapper()

    def encrypt(self, public_key: bytes, plaintext: bytes) -> bytes:
        """Encrypt data using hybrid approach."""
        # Generate ephemeral AES key
        ephemeral_key = secrets.token_bytes(AES_KEY_SIZE)

        # Encrypt data with AES-GCM
        cipher = AES256GCM(ephemeral_key)
        ciphertext, tag_nonce = cipher.encrypt(plaintext)

        # Wrap the AES key
        wrapped_key = self._key_wrapper.wrap_key(public_key, ephemeral_key)

        # Message format: [4-byte length][wrapped_key][28-byte tag_nonce][ciphertext]
        return (
            len(wrapped_key).to_bytes(4, "big") + wrapped_key + tag_nonce + ciphertext
        )

    def decrypt(self, private_key: bytes, data: bytes) -> bytes:
        """Decrypt hybrid-encrypted data."""
        try:
            # Parse structured message
            wrapped_key_len = int.from_bytes(data[:4], "big")
            wrapped_key = data[4 : 4 + wrapped_key_len]
            tag_nonce = data[4 + wrapped_key_len : 4 + wrapped_key_len + TAG_NONCE_SIZE]
            ciphertext = data[4 + wrapped_key_len + TAG_NONCE_SIZE :]

            # Unwrap the AES key
            ephemeral_key = self._key_wrapper.unwrap_key(private_key, wrapped_key)

            # Decrypt data with AES-GCM
            cipher = AES256GCM(ephemeral_key)
            return cipher.decrypt(ciphertext, tag_nonce)
        except (IndexError, ValueError) as e:
            msg = "Invalid message structure"
            raise ValueError(msg) from e
