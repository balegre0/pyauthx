__version__ = "1.0.0"
__author__ = "Brian Alegre"
__license__ = "MIT"
__copyright__ = "Copyright 2025-present balegre0"

import contextlib
import logging
from importlib.metadata import PackageNotFoundError

from .exceptions import (
    CryptographicError,
    InvalidTokenError,
    KeyRotationError,
    MTLSValidationError,
    SecurityError,
    TokenExpiredError,
    TokenReuseError,
)
from .facade import PyAuthX

contextlib.suppress(PackageNotFoundError)

logging.getLogger(__name__).addHandler(logging.NullHandler())

__all__ = [
    "CryptographicError",
    "InvalidTokenError",
    "KeyRotationError",
    "MTLSValidationError",
    "PyAuthX",
    "SecurityError",
    "TokenExpiredError",
    "TokenReuseError",
]
