class SecurityError(Exception):
    """Base para todas las excepciones de seguridad"""


class InvalidTokenError(SecurityError):
    """JWT inválido o manipulado"""


class TokenExpiredError(SecurityError):
    """JWT ha expirado"""


class TokenReuseError(SecurityError):
    """Intento de reutilización de refresh token"""


class KeyRotationError(SecurityError):
    """Error en rotación de claves"""


class mTLSValidationError(SecurityError):  # noqa: N801
    """Fallo en validación mTLS"""


class CryptographicError(SecurityError):
    """Error en operación criptográfica"""
