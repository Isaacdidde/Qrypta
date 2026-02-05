import secrets
import hashlib
import hmac
from datetime import datetime, timedelta
from typing import Tuple

from flask import current_app


# ==================================================
# Exceptions
# ==================================================

class OTPError(Exception):
    """Base OTP exception"""


class OTPExpiredError(OTPError):
    pass


class OTPAttemptsExceededError(OTPError):
    pass


class OTPInvalidError(OTPError):
    pass


# ==================================================
# OTP Generation
# ==================================================

def generate_otp() -> str:
    """
    Generate a cryptographically secure numeric OTP.
    Length is read from Flask config (OTP_LENGTH).
    """
    length = current_app.config["OTP_LENGTH"]
    digits = "0123456789"
    return "".join(secrets.choice(digits) for _ in range(length))


# ==================================================
# OTP Hashing
# ==================================================

def hash_otp(otp: str, salt: str) -> str:
    """
    Hash OTP using SHA-256 with a per-user salt.
    OTPs are short-lived, so SHA-256 is acceptable here.
    """
    value = f"{otp}{salt}".encode("utf-8")
    return hashlib.sha256(value).hexdigest()


# ==================================================
# OTP Expiry
# ==================================================

def otp_expiry_time() -> datetime:
    """
    Return OTP expiry datetime based on config.
    """
    minutes = current_app.config["OTP_EXPIRY_MINUTES"]
    return datetime.utcnow() + timedelta(minutes=minutes)


# ==================================================
# OTP Verification
# ==================================================

def verify_otp(
    *,
    provided_otp: str,
    stored_hash: str,
    salt: str,
    expires_at: datetime,
    attempts_used: int,
) -> Tuple[bool, int]:
    """
    Verify OTP securely.

    Returns:
        (is_valid, new_attempt_count)

    Raises:
        OTPExpiredError
        OTPAttemptsExceededError
        OTPInvalidError
    """

    # Expiry check
    if datetime.utcnow() > expires_at:
        raise OTPExpiredError("OTP has expired")

    # Attempt limit check
    max_attempts = current_app.config["OTP_MAX_ATTEMPTS"]
    if attempts_used >= max_attempts:
        raise OTPAttemptsExceededError(
            "Maximum OTP attempts exceeded"
        )

    # Hash provided OTP
    provided_hash = hash_otp(provided_otp, salt)

    # Constant-time comparison (timing-attack safe)
    if not hmac.compare_digest(provided_hash, stored_hash):
        raise OTPInvalidError("Invalid OTP")

    return True, attempts_used + 1
