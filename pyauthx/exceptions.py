class SecurityError(Exception):
    """Base class for all security-related exceptions"""


class InvalidTokenError(SecurityError):
    """Invalid or tampered JWT"""


class TokenExpiredError(SecurityError):
    """Expired JWT"""


class TokenReuseError(SecurityError):
    """Attempted refresh token reuse"""


class KeyRotationError(SecurityError):
    """Key rotation failure"""


class MTLSValidationError(SecurityError):
    """mTLS validation failure"""


class CryptographicError(SecurityError):
    """Cryptographic operation error"""


class UnsupportedAlgorithmError(CryptographicError):
    """Unsupported algorithm requested"""


class KeySizeError(CryptographicError):
    """Invalid key size"""


class ChainValidationError(Exception):
    """Base exception for chain validation failures."""


class CertificateExtensionError(ChainValidationError):
    """Raised when certificate extensions are invalid."""


class SignatureValidationError(ChainValidationError):
    """Raised when certificate signatures are invalid."""


class TrustAnchorError(ChainValidationError):
    """Raised when trust anchor verification fails."""
