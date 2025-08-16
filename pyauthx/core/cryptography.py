import secrets
from dataclasses import dataclass
from typing import Literal, Protocol, final, runtime_checkable

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .key_wrapper import KeyWrapper


@runtime_checkable
class KeyGenerator(Protocol):
    def generate(self, size: int) -> tuple[bytes, bytes]: ...


@final
@dataclass(frozen=True, slots=True)
class AES256GCM:
    @staticmethod
    def encrypt(
        key: bytes,
        plaintext: bytes,
        associated_data: bytes | None = None,
    ) -> tuple[bytes, bytes]:
        nonce = secrets.token_bytes(12)
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


AESKeySize = 32
TagNonceSize = 12 + 16


@final
class HybridEncryptor:
    __slots__ = ("_algorithm", "_key_generator")

    def __init__(
        self,
        key_generator: KeyGenerator,
        algorithm: Literal["EC"] = "EC",
    ) -> None:
        self._key_generator = key_generator
        self._algorithm = algorithm

    def encrypt(self, public_key: bytes, plaintext: bytes) -> bytes:
        ephemeral_key, _ = self._key_generator.generate(AESKeySize)
        ciphertext, tag_nonce = AES256GCM.encrypt(ephemeral_key, plaintext)
        wrapped_key = self._wrap_key(public_key, ephemeral_key)

        # Struct: [len wrapped_key: 4 bytes] [wrapped_key] [tag_nonce] [ciphertext]
        wrapped_key_len = len(wrapped_key).to_bytes(4, "big")
        return wrapped_key_len + wrapped_key + tag_nonce + ciphertext

    def decrypt(self, private_key: bytes, data: bytes) -> bytes:
        # Parser: [4 bytes len] [wrapped_key] [tag_nonce] [ciphertext]
        wrapped_key_len = int.from_bytes(data[:4], "big")
        wrapped_key = data[4 : 4 + wrapped_key_len]
        tag_nonce = data[4 + wrapped_key_len : 4 + wrapped_key_len + TagNonceSize]
        encrypted_data = data[4 + wrapped_key_len + TagNonceSize :]

        ephemeral_key = self._unwrap_key(private_key, wrapped_key)
        return AES256GCM.decrypt(ephemeral_key, encrypted_data, tag_nonce)

    def _wrap_key(self, public_key: bytes, key: bytes) -> bytes:
        return KeyWrapper.wrap_key(public_key, key, algorithm="EC")

    def _unwrap_key(self, private_key: bytes, wrapped_key: bytes) -> bytes:
        return KeyWrapper.unwrap_key(private_key, wrapped_key, algorithm="EC")
