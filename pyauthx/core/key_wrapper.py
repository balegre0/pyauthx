from __future__ import annotations

import os
from typing import Final, Literal, NoReturn, overload

from cryptography.exceptions import InvalidKey, InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)


class KeyWrapper:
    """Provides secure key wrapping using RSA-OAEP and ECIES encryption schemes.

    Supports two cryptographic protocols:
    1. RSA-OAEP: Optimal Asymmetric Encryption Padding for RSA
    2. ECIES: Elliptic Curve Integrated Encryption Scheme
    """

    _MIN_WRAPPED_KEY_LEN: Final[int] = 2  # Minimum valid wrapped key length
    RSA_WRAPPED_KEY_PREFIX: Final[int] = 0x01  # RSA key identifier
    ECIES_WRAPPED_KEY_PREFIX: Final[int] = 0x02  # ECIES key identifier
    _HKDF_INFO: Final[bytes] = b"ECIES Key Derivation"  # KDF context
    _HKDF_LENGTH: Final[int] = 32  # Derived key length (AES-256)
    VALID_KEY_SIZES: Final[tuple[int, ...]] = (16, 24, 32)  # AES key sizes

    @staticmethod
    @overload
    def wrap_key(
        public_key: bytes,
        plain_key: bytes,
        *,
        algorithm: Literal["RSA"],
    ) -> bytes: ...

    @staticmethod
    @overload
    def wrap_key(
        public_key: bytes,
        plain_key: bytes,
        *,
        algorithm: Literal["EC"],
    ) -> bytes: ...

    @staticmethod
    def wrap_key(
        public_key: bytes,
        plain_key: bytes,
        *,
        algorithm: Literal["RSA", "EC"] = "RSA",
    ) -> bytes:
        """Securely wrap (encrypt) a symmetric key using public key cryptography."""
        if len(plain_key) not in KeyWrapper.VALID_KEY_SIZES:
            KeyWrapper._fail("Key must be 16, 24 or 32 bytes for AES")

        try:
            if algorithm == "RSA":
                return KeyWrapper._rsa_oaep_wrap(public_key, plain_key)
            if algorithm == "EC":
                return KeyWrapper._ecies_wrap(public_key, plain_key)
            KeyWrapper._fail(f"Unsupported algorithm: '{algorithm}'")
        except (ValueError, TypeError, InvalidKey) as e:
            KeyWrapper._fail("Key wrapping failed", cause=e)

    @staticmethod
    def _rsa_oaep_wrap(public_key_pem: bytes, plain_key: bytes) -> bytes:
        """Wrap a key using RSA-OAEP encryption.

        Package format:
        [1 byte prefix][1 byte key size][N bytes ciphertext]
        """
        public_key = load_pem_public_key(public_key_pem, backend=default_backend())
        if not isinstance(public_key, rsa.RSAPublicKey):
            msg = "RSA public key required"
            raise TypeError(msg)

        ciphertext = public_key.encrypt(
            plain_key,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return bytes([KeyWrapper.RSA_WRAPPED_KEY_PREFIX, len(plain_key)]) + ciphertext

    @staticmethod
    def _ecies_wrap(public_key_pem: bytes, plain_key: bytes) -> bytes:
        """Wrap a key using ECIES encryption.

        Package format:
        [1 byte prefix][2 byte point size][N bytes ephemeral point]
        [12 bytes nonce][M bytes ciphertext]
        """
        public_key = load_pem_public_key(public_key_pem, backend=default_backend())
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            msg = "EC public key required"
            raise TypeError(msg)

        # Generate ephemeral key pair
        ephemeral_key = ec.generate_private_key(
            public_key.curve,
            backend=default_backend(),
        )
        ephemeral_pub = ephemeral_key.public_key()

        # Key derivation
        shared_key = ephemeral_key.exchange(ec.ECDH(), public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=KeyWrapper._HKDF_LENGTH,
            salt=None,
            info=KeyWrapper._HKDF_INFO,
            backend=default_backend(),
        ).derive(shared_key)

        # AES-GCM encryption
        nonce = os.urandom(12)
        ciphertext = AESGCM(derived_key).encrypt(
            nonce,
            plain_key,
            associated_data=None,
        )

        # Serialize components
        ephemeral_point = ephemeral_pub.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )

        return (
            bytes([KeyWrapper.ECIES_WRAPPED_KEY_PREFIX])
            + len(ephemeral_point).to_bytes(2, "big")
            + ephemeral_point
            + nonce
            + ciphertext
        )

    @staticmethod
    @overload
    def unwrap_key(
        private_key: bytes,
        wrapped_key: bytes,
        *,
        algorithm: Literal["RSA"],
    ) -> bytes: ...

    @staticmethod
    @overload
    def unwrap_key(
        private_key: bytes,
        wrapped_key: bytes,
        *,
        algorithm: Literal["EC"],
    ) -> bytes: ...

    @staticmethod
    def unwrap_key(
        private_key: bytes,
        wrapped_key: bytes,
        *,
        algorithm: Literal["RSA", "EC"] = "RSA",
    ) -> bytes:
        """Unwrap (decrypt) a previously wrapped symmetric key."""
        if not wrapped_key or len(wrapped_key) < KeyWrapper._MIN_WRAPPED_KEY_LEN:
            KeyWrapper._fail("Invalid wrapped key data")

        try:
            if algorithm == "RSA":
                return KeyWrapper._rsa_oaep_unwrap(private_key, wrapped_key)
            if algorithm == "EC":
                return KeyWrapper._ecies_unwrap(private_key, wrapped_key)
            KeyWrapper._fail(f"Unsupported algorithm: '{algorithm}'")
        except (ValueError, TypeError, InvalidKey, InvalidTag) as e:
            KeyWrapper._fail("Key unwrapping failed", cause=e)

    @staticmethod
    def _rsa_oaep_unwrap(private_key_pem: bytes, wrapped_key: bytes) -> bytes:
        """Unwrap an RSA-OAEP encrypted key package."""
        if wrapped_key[0] != KeyWrapper.RSA_WRAPPED_KEY_PREFIX:
            msg = "Invalid RSA wrapped key format"
            raise ValueError(msg)

        key_size = wrapped_key[1]
        ciphertext = wrapped_key[2:]

        private_key = load_pem_private_key(
            private_key_pem,
            password=None,
            backend=default_backend(),
        )
        if not isinstance(private_key, rsa.RSAPrivateKey):
            msg = "RSA private key required"
            raise TypeError(msg)

        plain_key = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        if len(plain_key) != key_size:
            msg = "Unwrapped key size mismatch"
            raise ValueError(msg)

        return plain_key

    @staticmethod
    def _ecies_unwrap(private_key_pem: bytes, wrapped_key: bytes) -> bytes:
        """Unwrap an ECIES encrypted key package."""
        if wrapped_key[0] != KeyWrapper.ECIES_WRAPPED_KEY_PREFIX:
            msg = "Invalid ECIES wrapped key format"
            raise ValueError(msg)

        # Parse package components
        ptr = 1
        ephem_size = int.from_bytes(wrapped_key[ptr : ptr + 2], "big")
        ptr += 2
        ephem_point = wrapped_key[ptr : ptr + ephem_size]
        ptr += ephem_size
        nonce = wrapped_key[ptr : ptr + 12]
        ptr += 12
        ciphertext = wrapped_key[ptr:]

        # Load private key
        private_key = load_pem_private_key(
            private_key_pem,
            password=None,
            backend=default_backend(),
        )
        if not isinstance(private_key, ec.EllipticCurvePrivateKey):
            msg = "EC private key required"
            raise TypeError(msg)

        # Reconstruct ephemeral public key
        ephemeral_pub = ec.EllipticCurvePublicKey.from_encoded_point(
            private_key.curve,
            ephem_point,
        )

        # Key derivation
        shared_key = private_key.exchange(ec.ECDH(), ephemeral_pub)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=KeyWrapper._HKDF_LENGTH,
            salt=None,
            info=KeyWrapper._HKDF_INFO,
            backend=default_backend(),
        ).derive(shared_key)

        # AES-GCM decryption
        try:
            return AESGCM(derived_key).decrypt(nonce, ciphertext, None)
        except InvalidTag as e:
            msg = "Authentication failed - key may be corrupted"
            raise ValueError(msg) from e

    @staticmethod
    def _fail(message: str, *, cause: Exception | None = None) -> NoReturn:
        """Uniform error handling for cryptographic operations."""
        if cause:
            raise ValueError(message) from cause
        raise ValueError(message)
