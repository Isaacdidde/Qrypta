import secrets
import hashlib
import hmac
from datetime import datetime, timedelta
from typing import Tuple


# ==================================================
# Exceptions
# ==================================================

class TokenError(Exception):
    """Base token exception"""


class TokenExpiredError(TokenError):
    pass


class TokenInvalidError(TokenError):
    pass


class TokenUsedError(TokenError):
    pass


# ==================================================
# Token Configuration (override via config if needed)
# ==================================================

DEFAULT_TOKEN_BYTES = 32          # 256-bit token
DEFAULT_TOKEN_EXPIRY_MINUTES = 15


# ==================================================
# Token Generation
# ==================================================

def generate_token() -> str:
    """
    Generate a cryptographically secure URL-safe token.
    Returned value is the *plaintext token* (send to user).
    """
    return secrets.token_urlsafe(DEFAULT_TOKEN_BYTES)


def hash_token(token: str, salt: str) -> str:
    """
    Hash token using SHA-256 + salt.
    Safe because token is high entropy and short-lived.
    """
    value = f"{token}{salt}".encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def token_expiry_time(
    minutes: int = DEFAULT_TOKEN_EXPIRY_MINUTES,
) -> datetime:
    return datetime.utcnow() + timedelta(minutes=minutes)


# ==================================================
# Token Verification
# ==================================================

def verify_token(
    *,
    provided_token: str,
    stored_hash: str,
    salt: str,
    expires_at: datetime,
    is_used: bool,
) -> None:
    """
    Verify a password reset / magic link token.

    Raises:
        TokenExpiredError
        TokenUsedError
        TokenInvalidError
    """

    if is_used:
        raise TokenUsedError("Token already used")

    if datetime.utcnow() > expires_at:
        raise TokenExpiredError("Token expired")

    provided_hash = hash_token(provided_token, salt)

    if not hmac.compare_digest(provided_hash, stored_hash):
        raise TokenInvalidError("Invalid token")
