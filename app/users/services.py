from bson import ObjectId
from flask import current_app
from flask_bcrypt import Bcrypt
from typing import Optional

from .models import (
    User,
    UserProfile,
    ROLE_PLATFORM_SUPERADMIN,
)


class UserService:
    """
    Handles user identity, roles, and profile-related logic.
    """

    def __init__(self, bcrypt: Bcrypt):
        self.bcrypt = bcrypt

    # ============================================================
    # Collections
    # ============================================================

    @property
    def users(self):
        return current_app.db.users

    @property
    def profiles(self):
        return current_app.db.user_profiles

    # ============================================================
    # User retrieval
    # ============================================================

    def get_user_by_id(self, user_id: str) -> Optional[User]:
        data = self.users.find_one({"_id": ObjectId(user_id)})
        if not data:
            return None
        return User.from_dict(data)

    def get_user_by_email(self, email: str) -> Optional[User]:
        data = self.users.find_one({"email": email.lower()})
        if not data:
            return None
        return User.from_dict(data)

    # ============================================================
    # Role helpers (CRITICAL for Option 1)
    # ============================================================

    @staticmethod
    def is_platform_admin(user: User) -> bool:
        return user.role == ROLE_PLATFORM_SUPERADMIN

    # ============================================================
    # Profile management
    # ============================================================

    def get_profile(self, user_id: str) -> Optional[UserProfile]:
        data = self.profiles.find_one({"user_id": ObjectId(user_id)})
        if not data:
            return None
        return UserProfile.from_dict(data)

    def create_or_update_profile(
        self,
        *,
        user_id: str,
        full_name: Optional[str] = None,
        phone: Optional[str] = None,
        mfa_question: Optional[str] = None,
        mfa_answer: Optional[str] = None,
    ) -> None:
        update_data = {
            "user_id": ObjectId(user_id),
            "full_name": full_name,
            "phone": phone,
        }

        if mfa_question and mfa_answer:
            update_data["mfa_question"] = mfa_question
            update_data["mfa_answer_hash"] = (
                self.bcrypt.generate_password_hash(mfa_answer).decode()
            )

        self.profiles.update_one(
            {"user_id": ObjectId(user_id)},
            {"$set": update_data},
            upsert=True,
        )

    # ============================================================
    # MFA verification
    # ============================================================

    def verify_mfa_answer(self, user_id: str, answer: str) -> bool:
        profile = self.profiles.find_one({"user_id": ObjectId(user_id)})
        if not profile:
            return False

        mfa_hash = profile.get("mfa_answer_hash")
        if not mfa_hash:
            return False

        return self.bcrypt.check_password_hash(mfa_hash, answer)

    # ============================================================
    # Account status helpers
    # ============================================================

    def is_active_user(self, user: User) -> bool:
        return user.is_active

    def deactivate_user(self, user_id: str) -> None:
        self.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"is_active": False}},
        )

    def update_last_login(self, user_id: str) -> None:
        self.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"last_login": current_app.utcnow()}},
        )
