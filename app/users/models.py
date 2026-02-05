from datetime import datetime
from typing import Optional
from bson import ObjectId


# ============================================================
# Role & Account Type Constants
# ============================================================

ROLE_PLATFORM_SUPERADMIN = "platform_superadmin"
ROLE_BUSINESS_ADMIN = "business_admin"
ROLE_MANAGER = "manager"
ROLE_EMPLOYEE = "employee"

ACCOUNT_PLATFORM = "platform"
ACCOUNT_BUSINESS = "business"


# ============================================================
# User Model
# ============================================================

class User:
    """
    Core authentication + authorization identity.
    """

    def __init__(
        self,
        *,
        email: str,
        password_hash: str,
        account_type: str,
        role: str,
        organization_id: Optional[ObjectId] = None,
        is_active: bool = True,
        full_name: Optional[str] = None,
        mobile: Optional[str] = None,
        company_name: Optional[str] = None,
        company_size: Optional[str] = None,
        business_address: Optional[dict] = None,
        _id: Optional[ObjectId] = None,
        created_at: Optional[datetime] = None,
        last_login: Optional[datetime] = None,
    ):
        self._id = _id or ObjectId()
        self.email = email.lower()
        self.password_hash = password_hash

        self.account_type = account_type
        self.role = role
        self.organization_id = organization_id

        self.is_active = is_active

        self.full_name = full_name
        self.mobile = mobile

        self.company_name = company_name
        self.company_size = company_size
        self.business_address = business_address or {}

        self.created_at = created_at or datetime.utcnow()
        self.last_login = last_login

    # -------------------------
    # Role helpers
    # -------------------------

    def is_platform_superadmin(self) -> bool:
        return self.role == ROLE_PLATFORM_SUPERADMIN

    def is_business_admin(self) -> bool:
        return self.role == ROLE_BUSINESS_ADMIN

    def is_employee(self) -> bool:
        return self.role in {ROLE_EMPLOYEE, ROLE_MANAGER}

    # -------------------------
    # Serialization
    # -------------------------

    def to_dict(self) -> dict:
        return {
            "_id": self._id,
            "email": self.email,
            "password_hash": self.password_hash,
            "account_type": self.account_type,
            "role": self.role,
            "organization_id": self.organization_id,
            "is_active": self.is_active,
            "full_name": self.full_name,
            "mobile": self.mobile,
            "company_name": self.company_name,
            "company_size": self.company_size,
            "business_address": self.business_address,
            "created_at": self.created_at,
            "last_login": self.last_login,
        }

    @staticmethod
    def from_dict(data: dict) -> "User":
        return User(
            _id=data.get("_id"),
            email=data["email"],
            password_hash=data["password_hash"],
            account_type=data["account_type"],
            role=data["role"],
            organization_id=data.get("organization_id"),
            is_active=data.get("is_active", True),
            full_name=data.get("full_name"),
            mobile=data.get("mobile"),
            company_name=data.get("company_name"),
            company_size=data.get("company_size"),
            business_address=data.get("business_address"),
            created_at=data.get("created_at"),
            last_login=data.get("last_login"),
        )


# ============================================================
# User Profile Model (MFA + Preferences)
# ============================================================

class UserProfile:
    """
    Represents user profile and preferences (separate collection).
    """

    def __init__(
        self,
        *,
        user_id: ObjectId,
        full_name: Optional[str] = None,
        phone: Optional[str] = None,
        mfa_question: Optional[str] = None,
        mfa_answer_hash: Optional[str] = None,
        updated_at: Optional[datetime] = None,
    ):
        self.user_id = user_id
        self.full_name = full_name
        self.phone = phone
        self.mfa_question = mfa_question
        self.mfa_answer_hash = mfa_answer_hash
        self.updated_at = updated_at or datetime.utcnow()

    def to_dict(self) -> dict:
        return {
            "user_id": self.user_id,
            "full_name": self.full_name,
            "phone": self.phone,
            "mfa_question": self.mfa_question,
            "mfa_answer_hash": self.mfa_answer_hash,
            "updated_at": self.updated_at,
        }

    @staticmethod
    def from_dict(data: dict) -> "UserProfile":
        return UserProfile(
            user_id=data["user_id"],
            full_name=data.get("full_name"),
            phone=data.get("phone"),
            mfa_question=data.get("mfa_question"),
            mfa_answer_hash=data.get("mfa_answer_hash"),
            updated_at=data.get("updated_at"),
        )
