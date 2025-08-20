from typing import Protocol, runtime_checkable

__all__ = ("KeyGeneratorProtocol", "KeyWrapperProtocol")


@runtime_checkable
class KeyWrapperProtocol(Protocol):
    """Protocol for key wrapping operations."""

    def wrap_key(self, public_key: bytes, plain_key: bytes) -> bytes:
        """Wrap a symmetric key using asymmetric encryption."""
        ...

    def unwrap_key(self, private_key: bytes, wrapped_key: bytes) -> bytes:
        """Unwrap an encrypted symmetric key."""
        ...


@runtime_checkable
class KeyGeneratorProtocol(Protocol):
    """Protocol for cryptographic key generation."""

    def generate(self, size: int) -> tuple[bytes, bytes]:
        """Generate a new cryptographic key pair."""
        ...
