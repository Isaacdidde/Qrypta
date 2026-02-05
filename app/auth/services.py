# app/auth/services.py

from datetime import datetime
import secrets

from flask import current_app
from flask_bcrypt import Bcrypt

from app.users.models import User
from app.core.otp import (
    generate_otp,
    hash_otp,
    otp_expiry_time,
    verify_otp,
    OTPExpiredError,
    OTPInvalidError,
    OTPAttemptsExceededError,
)
from app.core.password_strength import PasswordStrengthChecker
from app.auth.models import LoginOTP, PasswordResetOTP
from app.auth.email_service import AuthEmailService
from app.core.audit import AuditLogger


class AuthService:
    """
    Handles:
    - Registration
    - Login (password + OTP)
    - Password reset
    - Security auditing
    """

    def __init__(self, bcrypt: Bcrypt):
        # ✅ SINGLE bcrypt instance (critical)
        self.bcrypt = bcrypt
        self.email_service = AuthEmailService()
        self.audit = AuditLogger()

    # ==================================================
    # Collections
    # ==================================================
    @property
    def users(self):
        return current_app.db.users

    @property
    def login_otps(self):
        return current_app.db.login_otps

    @property
    def reset_otps(self):
        return current_app.db.password_reset_otps

    # ==================================================
    # Password policy
    # ==================================================
    @staticmethod
    def _validate_password(password: str) -> None:
        checker = PasswordStrengthChecker(password)
        if checker.entropy() < current_app.config["MIN_PASSWORD_ENTROPY"]:
            raise ValueError(
                "Password is too weak. Use a longer password with mixed characters."
            )

    # ==================================================
    # Registration
    # ==================================================
    def register_user(self, **kwargs) -> dict:
        password = kwargs.get("password")
        if not password:
            raise ValueError("Password is required")

        self._validate_password(password)

        email = kwargs["email"].lower().strip()
        account_type = kwargs["account_type"]

        if self.users.find_one({"email": email}):
            raise ValueError("User already exists")

        password_hash = self.bcrypt.generate_password_hash(password).decode()

        user = User(
            email=email,
            password_hash=password_hash,
            account_type=account_type,
            role="business_admin" if account_type == "business" else "user",
            full_name=kwargs.get("full_name"),
            mobile=kwargs.get("mobile"),
            company_name=kwargs.get("company_name"),
            company_size=kwargs.get("company_size"),
            business_address={
                "address": kwargs.get("address"),
                "city": kwargs.get("city"),
                "country": kwargs.get("country"),
                "pincode": kwargs.get("pincode"),
            }
            if account_type == "business"
            else None,
        )

        user_dict = user.to_dict()
        user_dict.update(
            {
                "created_at": datetime.utcnow(),
                "is_active": True,
                "last_login": None,
            }
        )

        result = self.users.insert_one(user_dict)
        user_dict["_id"] = result.inserted_id

        self.audit.log_event(
            user_id=str(user_dict["_id"]),
            action="auth.register.success",
            resource_type="user",
            resource_id=str(user_dict["_id"]),
        )

        return user_dict

    # ==================================================
    # LOGIN – STEP 1 (PASSWORD → OTP)
    # ==================================================
    def initiate_login_otp(
        self,
        *,
        email: str,
        password: str,
        ip_address: str | None,
        user_agent: str | None,
    ) -> None:
        email = email.lower().strip()
        user = self.users.find_one({"email": email})

        if not user:
            raise ValueError("Invalid credentials")

        if user.get("is_active") is False:
            raise ValueError("Account is disabled")

        # ✅ Correct bcrypt verification
        if not self.bcrypt.check_password_hash(
            user["password_hash"], password
        ):
            raise ValueError("Invalid credentials")

        # ---- OTP GENERATION ----
        otp = generate_otp()
        salt = secrets.token_hex(16)

        otp_doc = LoginOTP(
            user_id=user["_id"],
            otp_hash=hash_otp(otp, salt),
            salt=salt,
            expires_at=otp_expiry_time(),
            ip_address=ip_address,
            user_agent=user_agent,
        )

        # ✅ Only invalidate UNUSED OTPs (race-safe)
        self.login_otps.update_many(
            {"user_id": user["_id"], "is_used": False},
            {"$set": {"is_used": True}},
        )

        self.login_otps.insert_one(otp_doc.to_dict())

        try:
            self.email_service.send_login_otp(
                to_email=user["email"],
                otp=otp,
                user_id=str(user["_id"]),
                ip_address=ip_address,
            )
        except Exception:
            current_app.logger.exception("Login OTP email failed")
            raise ValueError("Unable to send OTP. Try again later.")

    # ==================================================
    # LOGIN – STEP 2 (VERIFY OTP)
    # ==================================================
    def verify_login_otp(
        self,
        *,
        email: str,
        otp: str,
        ip_address: str | None,
        user_agent: str | None,
    ) -> dict:
        email = email.lower().strip()
        user = self.users.find_one({"email": email})
        if not user:
            raise ValueError("Invalid session")

        otp_doc = self.login_otps.find_one(
            {"user_id": user["_id"], "is_used": False}
        )
        if not otp_doc:
            raise ValueError("OTP expired or invalid")

        try:
            verify_otp(
                provided_otp=otp,
                stored_hash=otp_doc["otp_hash"],
                salt=otp_doc["salt"],
                expires_at=otp_doc["expires_at"],
                attempts_used=otp_doc["attempts_used"],
            )
        except (OTPExpiredError, OTPInvalidError, OTPAttemptsExceededError):
            self.login_otps.update_one(
                {"_id": otp_doc["_id"]},
                {"$inc": {"attempts_used": 1}},
            )
            raise ValueError("Invalid or expired OTP")

        self.login_otps.update_one(
            {"_id": otp_doc["_id"]},
            {
                "$set": {
                    "is_used": True,
                    "verified_at": datetime.utcnow(),
                }
            },
        )

        self.users.update_one(
            {"_id": user["_id"]},
            {"$set": {"last_login": datetime.utcnow()}},
        )

        self.audit.log_event(
            user_id=str(user["_id"]),
            action="auth.login.success",
            resource_type="user",
            resource_id=str(user["_id"]),
        )

        return user

    # ==================================================
    # FORGOT PASSWORD – SEND OTP
    # ==================================================
    def initiate_password_reset(
        self,
        *,
        email: str,
        ip_address: str | None,
    ) -> None:
        email = email.lower().strip()
        user = self.users.find_one({"email": email})
        if not user:
            return  # anti-enumeration

        otp = generate_otp()
        salt = secrets.token_hex(16)

        reset_doc = PasswordResetOTP(
            user_id=user["_id"],
            otp_hash=hash_otp(otp, salt),
            salt=salt,
            expires_at=otp_expiry_time(),
            ip_address=ip_address,
        )

        self.reset_otps.update_many(
            {"user_id": user["_id"], "is_used": False},
            {"$set": {"is_used": True}},
        )

        self.reset_otps.insert_one(reset_doc.to_dict())

        try:
            self.email_service.send_forgot_password_otp(
                to_email=user["email"],
                otp=otp,
                user_id=str(user["_id"]),
                ip_address=ip_address,
            )
        except Exception:
            current_app.logger.exception("Password reset OTP email failed")

    # ==================================================
    # RESET PASSWORD – VERIFY OTP
    # ==================================================
    def reset_password_with_otp(
        self,
        *,
        email: str,
        otp: str,
        new_password: str,
        ip_address: str | None,
    ) -> None:
        self._validate_password(new_password)

        email = email.lower().strip()
        user = self.users.find_one({"email": email})
        if not user:
            raise ValueError("Invalid request")

        otp_doc = self.reset_otps.find_one(
            {"user_id": user["_id"], "is_used": False}
        )
        if not otp_doc:
            raise ValueError("OTP expired or invalid")

        try:
            verify_otp(
                provided_otp=otp,
                stored_hash=otp_doc["otp_hash"],
                salt=otp_doc["salt"],
                expires_at=otp_doc["expires_at"],
                attempts_used=otp_doc["attempts_used"],
            )
        except (OTPExpiredError, OTPInvalidError, OTPAttemptsExceededError):
            self.reset_otps.update_one(
                {"_id": otp_doc["_id"]},
                {"$inc": {"attempts_used": 1}},
            )
            raise ValueError("Invalid or expired OTP")

        new_hash = self.bcrypt.generate_password_hash(new_password).decode()

        self.users.update_one(
            {"_id": user["_id"]},
            {"$set": {"password_hash": new_hash}},
        )

        self.reset_otps.update_one(
            {"_id": otp_doc["_id"]},
            {
                "$set": {
                    "is_used": True,
                    "verified_at": datetime.utcnow(),
                }
            },
        )

        self.audit.log_event(
            user_id=str(user["_id"]),
            action="auth.password.reset",
            resource_type="user",
            resource_id=str(user["_id"]),
        )
