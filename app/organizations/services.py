# app/organizations/services.py

from datetime import datetime
from bson import ObjectId
from flask import current_app

from app.core.audit import AuditLogger
from .models import Organization, OrganizationMember


# ==================================================
# CONSTANTS
# ==================================================

AUTH_OWNER = "owner"
AUTH_ADMIN = "admin"
AUTH_MEMBER = "member"

ROLE_EMPLOYEE = "employee"
ROLE_MANAGER = "manager"

STATUS_ACTIVE = "active"
STATUS_SUSPENDED = "suspended"


# ==================================================
# ORGANIZATION SERVICE
# ==================================================

class OrganizationService:
    """
    Organization lifecycle + member management.

    Authority = power   (owner / admin / member)
    Role      = job     (employee / manager)
    """

    def __init__(self):
        self.audit = AuditLogger()

    # ==================================================
    # COLLECTIONS
    # ==================================================

    @property
    def orgs(self):
        return current_app.db.organizations

    @property
    def members(self):
        return current_app.db.organization_members

    @property
    def users(self):
        return current_app.db.users

    # ==================================================
    # PLATFORM
    # ==================================================

    def list_organizations(self) -> list:
        return list(self.orgs.find().sort("created_at", -1))

    # ==================================================
    # ORGANIZATION
    # ==================================================

    def create_organization(self, *, name: str, owner_id: str) -> ObjectId:
        owner_oid = ObjectId(owner_id)

        # Prevent duplicate org attachment
        user = self.users.find_one({"_id": owner_oid})
        if user.get("organization_id"):
            raise ValueError("User already belongs to an organization")

        org = Organization(
            name=name,
            owner_id=owner_oid,
            created_at=datetime.utcnow(),
        )

        result = self.orgs.insert_one(org.to_dict())
        org_id = result.inserted_id

        # Owner membership
        self.members.insert_one(
            OrganizationMember(
                org_id=org_id,
                user_id=owner_oid,
                authority=AUTH_OWNER,
                role=ROLE_EMPLOYEE,
                status=STATUS_ACTIVE,
                joined_at=datetime.utcnow(),
            ).to_dict()
        )

        # Attach org to owner
        self.users.update_one(
            {"_id": owner_oid},
            {
                "$set": {
                    "organization_id": org_id,
                    "account_type": "business",
                }
            },
        )

        self.audit.log_event(
            user_id=owner_id,
            org_id=str(org_id),
            action="org.created",
            resource_type="organization",
            resource_id=str(org_id),
        )

        return org_id

    def get_organization(self, org_id: str) -> dict | None:
        return self.orgs.find_one({"_id": ObjectId(org_id)})

    # ==================================================
    # MEMBERS (SORT + FILTER)
    # ==================================================

    def list_members(
        self,
        org_id: str,
        *,
        role=None,
        department=None,
        sort="new",
    ) -> list:

        pipeline = [
            {"$match": {"org_id": ObjectId(org_id)}},
            {
                "$lookup": {
                    "from": "users",
                    "localField": "user_id",
                    "foreignField": "_id",
                    "as": "user",
                }
            },
            {"$unwind": "$user"},
        ]

        filters = {}
        if role:
            filters["role"] = role
        if department:
            filters["department"] = department

        if filters:
            pipeline.append({"$match": filters})

        pipeline.append(
            {
                "$addFields": {
                    "authority_rank": {
                        "$switch": {
                            "branches": [
                                {"case": {"$eq": ["$authority", AUTH_OWNER]}, "then": 0},
                                {"case": {"$eq": ["$authority", AUTH_ADMIN]}, "then": 1},
                            ],
                            "default": 2,
                        }
                    }
                }
            }
        )

        sort_map = {
            "new": {"joined_at": -1},
            "old": {"joined_at": 1},
            "az": {"user.full_name": 1},
            "za": {"user.full_name": -1},
        }

        pipeline.append(
            {"$sort": {"authority_rank": 1, **sort_map.get(sort, {})}}
        )

        pipeline.append(
            {
                "$project": {
                    "_id": "$user._id",
                    "user_id": "$user._id",
                    "email": "$user.email",
                    "full_name": "$user.full_name",
                    "authority": "$authority",
                    "role": "$role",
                    "department": "$department",
                    "status": "$status",
                    "last_login": "$user.last_login",
                }
            }
        )

        return list(self.members.aggregate(pipeline))

    # ==================================================
    # AUTHORITY MANAGEMENT
    # ==================================================

    def set_authority(self, *, org_id, user_id, new_authority, actor_id):
        org_oid = ObjectId(org_id)
        user_oid = ObjectId(user_id)

        member = self.members.find_one(
            {"org_id": org_oid, "user_id": user_oid}
        )
        if not member:
            raise ValueError("Member not found")

        if member["authority"] == AUTH_OWNER:
            raise ValueError("Owner authority cannot be changed")

        # Prevent removing last admin
        if member["authority"] == AUTH_ADMIN and new_authority != AUTH_ADMIN:
            admin_count = self.members.count_documents(
                {"org_id": org_oid, "authority": AUTH_ADMIN}
            )
            if admin_count <= 1:
                raise ValueError("Organization must have at least one admin")

        self.members.update_one(
            {"org_id": org_oid, "user_id": user_oid},
            {
                "$set": {
                    "authority": new_authority,
                    "updated_at": datetime.utcnow(),
                }
            },
        )

        self.audit.log_event(
            user_id=actor_id,
            org_id=org_id,
            action="org.member.authority_changed",
            resource_type="organization",
            resource_id=org_id,
            metadata={
                "target_user": user_id,
                "authority": new_authority,
            },
        )

    # ==================================================
    # ROLE MANAGEMENT
    # ==================================================

    def set_role(self, *, org_id, user_id, new_role, actor_id):
        self.members.update_one(
            {"org_id": ObjectId(org_id), "user_id": ObjectId(user_id)},
            {
                "$set": {
                    "role": new_role,
                    "updated_at": datetime.utcnow(),
                }
            },
        )

        self.audit.log_event(
            user_id=actor_id,
            org_id=org_id,
            action="org.member.role_changed",
            resource_type="organization",
            resource_id=org_id,
            metadata={
                "target_user": user_id,
                "role": new_role,
            },
        )

    # ==================================================
    # STATUS MANAGEMENT
    # ==================================================

    def suspend_member(self, *, org_id, user_id, actor_id):
        if user_id == actor_id:
            raise ValueError("You cannot suspend yourself")

        self.members.update_one(
            {"org_id": ObjectId(org_id), "user_id": ObjectId(user_id)},
            {
                "$set": {
                    "status": STATUS_SUSPENDED,
                    "updated_at": datetime.utcnow(),
                }
            },
        )

    def reactivate_member(self, *, org_id, user_id, actor_id):
        self.members.update_one(
            {"org_id": ObjectId(org_id), "user_id": ObjectId(user_id)},
            {
                "$set": {
                    "status": STATUS_ACTIVE,
                    "updated_at": datetime.utcnow(),
                }
            },
        )

    def remove_member(self, *, org_id, user_id, actor_id):
        member = self.members.find_one(
            {"org_id": ObjectId(org_id), "user_id": ObjectId(user_id)}
        )
        if not member:
            return

        if member["authority"] == AUTH_OWNER:
            raise ValueError("Owner cannot be removed")

        if member["authority"] == AUTH_ADMIN:
            admin_count = self.members.count_documents(
                {"org_id": ObjectId(org_id), "authority": AUTH_ADMIN}
            )
            if admin_count <= 1:
                raise ValueError("Organization must have at least one admin")

        self.members.delete_one(
            {"org_id": ObjectId(org_id), "user_id": ObjectId(user_id)}
        )

        self.users.update_one(
            {"_id": ObjectId(user_id)},
            {
                "$unset": {"organization_id": ""},
                "$set": {"account_type": "individual"},
            },
        )

        self.audit.log_event(
            user_id=actor_id,
            org_id=org_id,
            action="org.member.removed",
            resource_type="organization",
            resource_id=org_id,
            metadata={"target_user": user_id},
        )
