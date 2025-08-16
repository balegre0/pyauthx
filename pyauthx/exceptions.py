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
