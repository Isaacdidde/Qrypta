from datetime import datetime, timedelta
from bson import ObjectId
import secrets


# ==================================================
# ORGANIZATION INVITATION
# ==================================================

class OrganizationInvitation:
    """
    Represents an email-based invitation to join an organization.

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
        role: str,
        invited_by: ObjectId,
        department: str | None = None,
        expires_in_days: int = 7,
    ):
        if not isinstance(org_id, ObjectId):
            raise TypeError("org_id must be ObjectId")

        if not isinstance(invited_by, ObjectId):
            raise TypeError("invited_by must be ObjectId")

        self.org_id = org_id
        self.email = email.lower().strip()

        self.role = role
        self.department = department

        self.invited_by = invited_by

        self.token = secrets.token_urlsafe(32)
        self.status = self.STATUS_INVITED

        self.invited_at = datetime.utcnow()
        self.expires_at = self.invited_at + timedelta(days=expires_in_days)
        self.accepted_at = None

    # -----------------------------
    # Helpers
    # -----------------------------

    def is_expired(self) -> bool:
        return datetime.utcnow() > self.expires_at

    def to_dict(self) -> dict:
        """
        Serialize invitation for MongoDB.
        """
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
