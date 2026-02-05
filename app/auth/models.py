# app/auth/models.py

from datetime import datetime
from typing import Optional

from bson import ObjectId


# =========================================================
# LOGIN OTP MODEL
# =========================================================

class LoginOTP:
    """
    One-time password used during login (2FA).

    Security properties:
    - Hashed (never store raw OTP)
    - Time-bound
    - Attempt-limited
    - Single-use
    """

    def __init__(
        self,
        *,
        user_id: ObjectId,
        otp_hash: str,
        salt: str,
        expires_at: datetime,
        attempts_used: int = 0,
        is_used: bool = False,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ):
        self.user_id = user_id
        self.otp_hash = otp_hash
        self.salt = salt
        self.expires_at = expires_at

        self.attempts_used = attempts_used
        self.is_used = is_used

        # Context (for audit / anomaly detection)
        self.ip_address = ip_address
        self.user_agent = user_agent

        self.created_at = datetime.utcnow()
        self.verified_at: Optional[datetime] = None

    def to_dict(self) -> dict:
        return {
            "user_id": self.user_id,
            "otp_hash": self.otp_hash,
            "salt": self.salt,
            "expires_at": self.expires_at,
            "attempts_used": self.attempts_used,
            "is_used": self.is_used,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "created_at": self.created_at,
            "verified_at": self.verified_at,
        }

    @staticmethod
    def from_dict(data: dict) -> "LoginOTP":
        otp = LoginOTP(
            user_id=data["user_id"],
            otp_hash=data["otp_hash"],
            salt=data["salt"],
            expires_at=data["expires_at"],
            attempts_used=data.get("attempts_used", 0),
            is_used=data.get("is_used", False),
            ip_address=data.get("ip_address"),
            user_agent=data.get("user_agent"),
        )

        otp.created_at = data.get("created_at")
        otp.verified_at = data.get("verified_at")
        return otp


# =========================================================
# PASSWORD RESET OTP MODEL
# =========================================================

class PasswordResetOTP:
    """
    OTP used for password recovery.

    Kept separate from LoginOTP to allow:
    - Different expiry
    - Different attempt limits
    - Independent revocation
    """

    def __init__(
        self,
        *,
        user_id: ObjectId,
        otp_hash: str,
        salt: str,
        expires_at: datetime,
        attempts_used: int = 0,
        is_used: bool = False,
        ip_address: Optional[str] = None,
    ):
        self.user_id = user_id
        self.otp_hash = otp_hash
        self.salt = salt
        self.expires_at = expires_at

        self.attempts_used = attempts_used
        self.is_used = is_used

        self.ip_address = ip_address

        self.created_at = datetime.utcnow()
        self.verified_at: Optional[datetime] = None

    def to_dict(self) -> dict:
        return {
            "user_id": self.user_id,
            "otp_hash": self.otp_hash,
            "salt": self.salt,
            "expires_at": self.expires_at,
            "attempts_used": self.attempts_used,
            "is_used": self.is_used,
            "ip_address": self.ip_address,
            "created_at": self.created_at,
            "verified_at": self.verified_at,
        }

    @staticmethod
    def from_dict(data: dict) -> "PasswordResetOTP":
        otp = PasswordResetOTP(
            user_id=data["user_id"],
            otp_hash=data["otp_hash"],
            salt=data["salt"],
            expires_at=data["expires_at"],
            attempts_used=data.get("attempts_used", 0),
            is_used=data.get("is_used", False),
            ip_address=data.get("ip_address"),
        )

        otp.created_at = data.get("created_at")
        otp.verified_at = data.get("verified_at")
        return otp


# =========================================================
# AUTH LOG MODEL (DOMAIN-LOCAL)
# =========================================================

class AuthLog:
    """
    Immutable authentication event record.

    Stored separately from audit logs to:
    - avoid circular dependencies
    - allow selective retention
    - enable security analytics
    """

    def __init__(
        self,
        *,
        event_type: str,
        success: bool,
        user_id: Optional[ObjectId] = None,
        email: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[dict] = None,
    ):
        self.event_type = event_type
        self.success = success

        self.user_id = user_id
        self.email = email

        self.ip_address = ip_address
        self.user_agent = user_agent

        self.metadata = metadata or {}

        self.created_at = datetime.utcnow()

    def to_dict(self) -> dict:
        return {
            "event_type": self.event_type,
            "success": self.success,
            "user_id": self.user_id,
            "email": self.email,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "metadata": self.metadata,
            "created_at": self.created_at,
        }
