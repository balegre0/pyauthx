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
    """Impl key wrapping using RSA-OAEP and ECIES."""

    _MIN_WRAPPED_KEY_LEN: Final[int] = 2
    RSA_WRAPPED_KEY_PREFIX: Final[int] = 0x01
    ECIES_WRAPPED_KEY_PREFIX: Final[int] = 0x02
    _HKDF_INFO: Final[bytes] = b"ECIES Key Derivation"
    _HKDF_LENGTH: Final[int] = 32

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
        if len(plain_key) not in (16, 24, 32):
            KeyWrapper._fail("La clave debe ser de 16, 24 o 32 bytes para AES")

        try:
            if algorithm == "RSA":
                return KeyWrapper._rsa_oaep_wrap(public_key, plain_key)
            if algorithm == "EC":
                return KeyWrapper._ecies_wrap(public_key, plain_key)
            KeyWrapper._fail(f"Algoritmo '{algorithm}' no soportado")
        except (ValueError, TypeError, InvalidKey) as e:
            KeyWrapper._fail(str(e), cause=e)

    @staticmethod
    def _rsa_oaep_wrap(public_key_pem: bytes, plain_key: bytes) -> bytes:
        public_key = load_pem_public_key(public_key_pem, backend=default_backend())
        if not isinstance(public_key, rsa.RSAPublicKey):
            msg = "Se requiere una clave pública RSA"
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
        public_key = load_pem_public_key(public_key_pem, backend=default_backend())
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            msg = "Se requiere una clave pública EC"
            raise TypeError(msg)

        ephemeral_key = ec.generate_private_key(
            public_key.curve,
            backend=default_backend(),
        )
        ephemeral_pub = ephemeral_key.public_key()

        shared_key = ephemeral_key.exchange(ec.ECDH(), public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=KeyWrapper._HKDF_LENGTH,
            salt=None,
            info=KeyWrapper._HKDF_INFO,
            backend=default_backend(),
        ).derive(shared_key)

        nonce = os.urandom(12)
        ciphertext = AESGCM(derived_key).encrypt(
            nonce,
            plain_key,
            associated_data=None,
        )

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
        if not wrapped_key or len(wrapped_key) < KeyWrapper._MIN_WRAPPED_KEY_LEN:
            KeyWrapper._fail("Datos de clave envuelta inválidos")

        try:
            if algorithm == "RSA":
                return KeyWrapper._rsa_oaep_unwrap(private_key, wrapped_key)
            if algorithm == "EC":
                return KeyWrapper._ecies_unwrap(private_key, wrapped_key)
            KeyWrapper._fail(f"Algoritmo '{algorithm}' no soportado")
        except (ValueError, TypeError, InvalidKey, InvalidTag) as e:
            KeyWrapper._fail("Error al desenvolver clave", cause=e)

    @staticmethod
    def _rsa_oaep_unwrap(private_key_pem: bytes, wrapped_key: bytes) -> bytes:
        if wrapped_key[0] != KeyWrapper.RSA_WRAPPED_KEY_PREFIX:
            msg = "Formato de clave RSA envuelta inválido"
            raise ValueError(msg)

        key_size = wrapped_key[1]
        ciphertext = wrapped_key[2:]

        private_key = load_pem_private_key(
            private_key_pem,
            password=None,
            backend=default_backend(),
        )
        if not isinstance(private_key, rsa.RSAPrivateKey):
            msg = "Se requiere una clave privada RSA"
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
            msg = "El tamaño de clave desenvuelta no coincide"
            raise ValueError(msg)

        return plain_key

    @staticmethod
    def _ecies_unwrap(private_key_pem: bytes, wrapped_key: bytes) -> bytes:
        if wrapped_key[0] != KeyWrapper.ECIES_WRAPPED_KEY_PREFIX:
            msg = "Formato de clave EC envuelta inválido"
            raise ValueError(msg)

        ptr = 1
        ephem_size = int.from_bytes(wrapped_key[ptr : ptr + 2], "big")
        ptr += 2
        ephem_point = wrapped_key[ptr : ptr + ephem_size]
        ptr += ephem_size
        nonce = wrapped_key[ptr : ptr + 12]
        ptr += 12
        ciphertext = wrapped_key[ptr:]

        private_key = load_pem_private_key(
            private_key_pem,
            password=None,
            backend=default_backend(),
        )
        if not isinstance(private_key, ec.EllipticCurvePrivateKey):
            msg = "Se requiere una clave privada EC"
            raise TypeError(msg)

        ephemeral_pub = ec.EllipticCurvePublicKey.from_encoded_point(
            private_key.curve,
            ephem_point,
        )
        shared_key = private_key.exchange(ec.ECDH(), ephemeral_pub)

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=KeyWrapper._HKDF_LENGTH,
            salt=None,
            info=KeyWrapper._HKDF_INFO,
            backend=default_backend(),
        ).derive(shared_key)

        try:
            return AESGCM(derived_key).decrypt(nonce, ciphertext, None)
        except InvalidTag as e:
            msg = "Autenticación fallida, clave corrupta o manipulada"
            raise ValueError(msg) from e

    @staticmethod
    def _fail(msg: str, *, cause: Exception | None = None) -> NoReturn:
        if cause:
            raise ValueError(msg) from cause
        raise ValueError(msg)
