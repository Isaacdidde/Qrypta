# app/organizations/models.py

from datetime import datetime, timedelta
from bson import ObjectId
import secrets
from typing import Optional


# ===================================================
# ORGANIZATION
# ===================================================

class Organization:
    """
    Represents a business organization.

    - One owner
    - Many members
    """

    def __init__(
        self,
        *,
        name: str,
        owner_id: ObjectId,
        is_active: bool = True,
        created_at: Optional[datetime] = None,
        updated_at: Optional[datetime] = None,
    ):
        self.name = name
        self.owner_id = owner_id
        self.is_active = is_active

        now = datetime.utcnow()
        self.created_at = created_at or now
        self.updated_at = updated_at or now

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "owner_id": self.owner_id,
            "is_active": self.is_active,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


# ===================================================
# ORGANIZATION MEMBER
# ===================================================

class OrganizationMember:
    """
    Represents a user's membership in an organization.

    authority → power
        - owner
        - admin
        - member

    role → job function
        - employee
        - manager

    department → org grouping
    """

    # -----------------------------
    # Authority
    # -----------------------------
    AUTHORITY_OWNER = "owner"
    AUTHORITY_ADMIN = "admin"
    AUTHORITY_MEMBER = "member"

    # -----------------------------
    # Status
    # -----------------------------
    STATUS_ACTIVE = "active"
    STATUS_INVITED = "invited"
    STATUS_SUSPENDED = "suspended"

    def __init__(
        self,
        *,
        org_id: ObjectId,
        user_id: ObjectId,
        authority: str = AUTHORITY_MEMBER,
        role: str = "employee",
        department: Optional[str] = None,
        status: str = STATUS_ACTIVE,
        invited_by: Optional[ObjectId] = None,
        joined_at: Optional[datetime] = None,
        updated_at: Optional[datetime] = None,
    ):
        self.org_id = org_id
        self.user_id = user_id

        self.authority = authority
        self.role = role
        self.department = department

        self.status = status
        self.invited_by = invited_by

        now = datetime.utcnow()
        self.joined_at = joined_at or now
        self.updated_at = updated_at or now

    # -----------------------------
    # Authority helpers
    # -----------------------------
    def is_owner(self) -> bool:
        return self.authority == self.AUTHORITY_OWNER

    def is_admin(self) -> bool:
        return self.authority in (
            self.AUTHORITY_OWNER,
            self.AUTHORITY_ADMIN,
        )

    def to_dict(self) -> dict:
        return {
            "org_id": self.org_id,
            "user_id": self.user_id,
            "authority": self.authority,
            "role": self.role,
            "department": self.department,
            "status": self.status,
            "invited_by": self.invited_by,
            "joined_at": self.joined_at,
            "updated_at": self.updated_at,
        }


# ===================================================
# ORGANIZATION INVITATION
# ===================================================

class OrganizationInvitation:
    """
    Email-based invitation to join an organization.

    Lifecycle:
        invited → accepted | expired | revoked
    """

    STATUS_INVITED = "invited"
    STATUS_ACCEPTED = "accepted"
    STATUS_EXPIRED = "expired"
    STATUS_REVOKED = "revoked"

    def __init__(
        self,
        *,
        org_id: ObjectId,
        email: str,
        role: str = "employee",
        department: Optional[str] = None,
        invited_by: ObjectId,
        expires_in_days: int = 7,
        invited_at: Optional[datetime] = None,
        accepted_at: Optional[datetime] = None,
        status: Optional[str] = None,
        token: Optional[str] = None,
    ):
        self.org_id = org_id
        self.email = email.lower().strip()

        self.role = role
        self.department = department
        self.invited_by = invited_by

        self.token = token or secrets.token_urlsafe(32)
        self.status = status or self.STATUS_INVITED

        self.invited_at = invited_at or datetime.utcnow()
        self.expires_at = self.invited_at + timedelta(days=expires_in_days)
        self.accepted_at = accepted_at

    # -----------------------------
    # Helpers
    # -----------------------------
    def is_expired(self) -> bool:
        return datetime.utcnow() > self.expires_at

    def to_dict(self) -> dict:
        return {
            "org_id": self.org_id,
            "email": self.email,
            "role": self.role,
            "department": self.department,
            "invited_by": self.invited_by,
            "token": self.token,
            "status": self.status,
            "invited_at": self.invited_at,
            "expires_at": self.expires_at,
            "accepted_at": self.accepted_at,
        }
