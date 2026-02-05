from datetime import datetime
from bson import ObjectId
from flask import current_app, request

from app.core.audit import AuditLogger
from app.organizations.invitations.models import OrganizationInvitation
from app.organizations.models import OrganizationMember
from app.organizations.invitations.email_service import (
    InvitationEmailService,
    InvitationEmailError,
)

# ==================================================
# CONSTANTS
# ==================================================

STATUS_INVITED = "invited"
STATUS_ACCEPTED = "accepted"
STATUS_EXPIRED = "expired"
STATUS_REVOKED = "revoked"

ALLOWED_ROLES = {"employee", "manager", "business_admin"}
ALLOWED_INVITERS = ("owner", "admin")


# ==================================================
# INVITATION SERVICE
# ==================================================

class InvitationService:
    """
    Handles organization invitations:
    - Create / resend invitations
    - Email delivery
    - Token validation
    - Accept / revoke invitations
    """

    def __init__(self):
        self.audit = AuditLogger()
        self.email_service = InvitationEmailService()

    # -----------------------------
    # Collections
    # -----------------------------

    @property
    def invitations(self):
        return current_app.db.organization_invitations

    @property
    def members(self):
        return current_app.db.organization_members

    @property
    def users(self):
        return current_app.db.users

    @property
    def organizations(self):
        return current_app.db.organizations

    # -----------------------------
    # Invite / Resend
    # -----------------------------

    def invite(
        self,
        *,
        org_id: str,
        email: str,
        role: str,
        invited_by: str,
        department: str | None = None,
        expires_in_days: int = 7,
    ) -> str:

        email = email.lower().strip()
        org_oid = ObjectId(org_id)
        inviter_oid = ObjectId(invited_by)

        if role not in ALLOWED_ROLES:
            raise ValueError("Invalid role")

        # --------------------------------------------------
        # Permission check
        # --------------------------------------------------
        inviter = self.members.find_one(
            {
                "org_id": org_oid,
                "user_id": inviter_oid,
                "status": "active",
                "authority": {"$in": ALLOWED_INVITERS},
            }
        )

        if not inviter:
            raise PermissionError("Insufficient permissions to invite users")

        # --------------------------------------------------
        # Prevent inviting existing members
        # --------------------------------------------------
        existing_user = self.users.find_one({"email": email})
        if existing_user and self.members.find_one(
            {"org_id": org_oid, "user_id": existing_user["_id"]}
        ):
            raise ValueError("User is already a member of this organization")

        # --------------------------------------------------
        # Check for existing active invitation → RESEND
        # --------------------------------------------------
        existing_invite = self.invitations.find_one(
            {
                "org_id": org_oid,
                "email": email,
                "status": STATUS_INVITED,
            }
        )

        if existing_invite:
            self._send_email(existing_invite, invited_by, org_oid)

            self.audit.log_event(
                user_id=invited_by,
                org_id=org_id,
                action="org.invitation.resent",
                resource_type="invitation",
                resource_id=existing_invite["token"],
                metadata={"email": email},
            )

            return existing_invite["token"]

        # --------------------------------------------------
        # Create new invitation
        # --------------------------------------------------
        invitation = OrganizationInvitation(
            org_id=org_oid,
            email=email,
            role=role,
            department=department,
            invited_by=inviter_oid,
            expires_in_days=expires_in_days,
        )

        self.invitations.insert_one(invitation.to_dict())

        self._send_email(invitation.to_dict(), invited_by, org_oid)

        self.audit.log_event(
            user_id=invited_by,
            org_id=org_id,
            action="org.invitation.sent",
            resource_type="invitation",
            resource_id=invitation.token,
            metadata={
                "email": email,
                "role": role,
                "department": department,
            },
        )

        return invitation.token

    # -----------------------------
    # Accept invitation
    # -----------------------------

    def accept_invitation(self, *, token: str, user_id: str):
        invite = self.validate_token(token)
        user_oid = ObjectId(user_id)

        if self.members.find_one(
            {"org_id": invite["org_id"], "user_id": user_oid}
        ):
            raise ValueError("User is already a member of this organization")

        self.members.insert_one(
            OrganizationMember(
                org_id=invite["org_id"],
                user_id=user_oid,
                role=invite["role"],
                department=invite.get("department"),
                authority="member",
                status="active",
                invited_by=invite.get("invited_by"),
            ).to_dict()
        )

        self.invitations.update_one(
            {"_id": invite["_id"]},
            {
                "$set": {
                    "status": STATUS_ACCEPTED,
                    "accepted_at": datetime.utcnow(),
                }
            },
        )

        self.users.update_one(
            {"_id": user_oid},
            {
                "$set": {
                    "organization_id": invite["org_id"],
                    "account_type": "business",
                }
            },
        )

        self.audit.log_event(
            user_id=user_id,
            org_id=str(invite["org_id"]),
            action="org.invitation.accepted",
            resource_type="invitation",
            resource_id=invite["token"],
        )

    # -----------------------------
    # Validate token
    # -----------------------------

    def validate_token(self, token: str) -> dict:
        invite = self.invitations.find_one({"token": token})
        if not invite:
            raise ValueError("Invalid invitation")

        if invite["status"] != STATUS_INVITED:
            raise ValueError("Invitation already used or revoked")

        if invite["expires_at"] < datetime.utcnow():
            self.invitations.update_one(
                {"_id": invite["_id"]},
                {"$set": {"status": STATUS_EXPIRED}},
            )
            raise ValueError("Invitation expired")

        return invite

    # -----------------------------
    # Alias (do not remove)
    # -----------------------------

    def accept(self, *, token: str, user_id: str):
        return self.accept_invitation(token=token, user_id=user_id)

    # -----------------------------
    # Internal email helper
    # -----------------------------

    def _send_email(self, invite: dict, invited_by: str, org_oid: ObjectId):
        org = self.organizations.find_one({"_id": org_oid})
        org_name = org.get("name", "Your Organization") if org else "Your Organization"

        base_url = current_app.config.get(
            "APP_BASE_URL",
            request.host_url.rstrip("/"),
        )

        invite_url = f"{base_url}/organizations/accept/{invite['token']}"

        try:
            self.email_service.send_invitation(
                to_email=invite["email"],
                invite_url=invite_url,
                org_name=org_name,
                invited_by=invited_by,
                org_id=str(org_oid),
            )
        except InvitationEmailError:
            current_app.logger.exception("Invitation email failed")
