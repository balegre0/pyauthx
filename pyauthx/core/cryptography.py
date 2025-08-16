from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Final, Protocol, final, runtime_checkable

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .key_wrapper import KeyWrapper

# Constants
AES_KEY_SIZE: Final[int] = 32  # 256-bit AES key
TAG_NONCE_SIZE: Final[int] = 28  # 12-byte nonce + 16-byte GCM tag


@runtime_checkable
class KeyGenerator(Protocol):
    """Protocol defining the interface for cryptographic key generation."""

    def generate(self, size: int) -> tuple[bytes, bytes]:
        """Generate a new cryptographic key pair."""
        ...


@final
@dataclass(frozen=True, slots=True)
class AES256GCM:
    """Authenticated encryption using AES-256 in GCM mode.

    Provides static methods for encryption/decryption with:
    - 256-bit AES keys
    - 12-byte random nonces
    - 16-byte authentication tags
    - Optional additional authenticated data (AAD)
    """

    @staticmethod
    def encrypt(
        key: bytes,
        plaintext: bytes,
        associated_data: bytes | None = None,
    ) -> tuple[bytes, bytes]:
        """Encrypt data with AES-256-GCM."""
        if len(key) != AES_KEY_SIZE:
            msg = f"AES-256 requires {AES_KEY_SIZE}-byte key"
            raise ValueError(msg)

        nonce = secrets.token_bytes(12)  # Cryptographically secure random nonce
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
            backend=default_backend(),
        )

        encryptor = cipher.encryptor()
        if associated_data:
            encryptor.authenticate_additional_data(associated_data)

        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return ciphertext, nonce + encryptor.tag

    @staticmethod
    def decrypt(
        key: bytes,
        ciphertext: bytes,
        nonce_tag: bytes,
        associated_data: bytes | None = None,
    ) -> bytes:
        """Decrypt AES-256-GCM encrypted data."""
        if len(nonce_tag) != TAG_NONCE_SIZE:
            msg = "Invalid nonce+tag length"
            raise ValueError(msg)
        if len(key) != AES_KEY_SIZE:
            msg = f"AES-256 requires {AES_KEY_SIZE}-byte key"
            raise ValueError(msg)

        nonce, tag = nonce_tag[:12], nonce_tag[12:]
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce, tag),
            backend=default_backend(),
        )
        decryptor = cipher.decryptor()

        if associated_data:
            decryptor.authenticate_additional_data(associated_data)

        return decryptor.update(ciphertext) + decryptor.finalize()


@final
class HybridEncryptor:
    """Combines asymmetric key wrapping with symmetric AES-256-GCM encryption.

    Implements a secure hybrid cryptosystem that:
    1. Generates ephemeral AES keys per encryption
    2. Wraps keys using elliptic curve cryptography
    3. Encrypts data with AES-256-GCM
    """

    __slots__ = ("_key_generator",)

    def __init__(
        self,
        key_generator: KeyGenerator,
    ) -> None:
        """Initialize the hybrid encryptor."""
        self._key_generator = key_generator

    def encrypt(self, public_key: bytes, plaintext: bytes) -> bytes:
        """Encrypt data using hybrid approach."""
        ephemeral_key, _ = self._key_generator.generate(AES_KEY_SIZE)
        ciphertext, tag_nonce = AES256GCM.encrypt(ephemeral_key, plaintext)
        wrapped_key = self._wrap_key(public_key, ephemeral_key)

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
            encrypted_data = data[4 + wrapped_key_len + TAG_NONCE_SIZE :]

            ephemeral_key = self._unwrap_key(private_key, wrapped_key)
            return AES256GCM.decrypt(ephemeral_key, encrypted_data, tag_nonce)
        except (IndexError, ValueError) as e:
            msg = "Invalid message structure"
            raise ValueError(msg) from e

    def _wrap_key(self, public_key: bytes, key: bytes) -> bytes:
        """Wrap an AES key using public key cryptography."""
        return KeyWrapper.wrap_key(public_key, key, algorithm="EC")

    def _unwrap_key(self, private_key: bytes, wrapped_key: bytes) -> bytes:
        """Unwrap an encrypted AES key using private key."""
        return KeyWrapper.unwrap_key(
            private_key,
            wrapped_key,
            algorithm="EC",
        )
