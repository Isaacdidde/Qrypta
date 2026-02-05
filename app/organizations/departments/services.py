from datetime import datetime
from bson import ObjectId
from flask import current_app

from app.core.audit import AuditLogger
from .models import Department, DepartmentMember


# ==================================================
# CONSTANTS
# ==================================================

ROLE_OWNER = "owner"
ROLE_ADMIN = "business_admin"
ROLE_MANAGER = "manager"

DEPT_ROLE_MEMBER = "member"
DEPT_ROLE_LEAD = "lead"
DEPT_ROLE_HEAD = "head"


# ==================================================
# DEPARTMENT SERVICE
# ==================================================

class DepartmentService:
    """
    Handles department lifecycle and department membership.
    """

    def __init__(self):
        self.audit = AuditLogger()

    # -----------------------------
    # Collection helpers
    # -----------------------------

    @property
    def departments(self):
        return current_app.db.departments

    @property
    def department_members(self):
        return current_app.db.department_members

    @property
    def org_members(self):
        return current_app.db.organization_members

    # -----------------------------
    # Internal helpers
    # -----------------------------

    def _require_org_admin(self, *, org_id: ObjectId, user_id: ObjectId):
        member = self.org_members.find_one(
            {
                "org_id": org_id,
                "user_id": user_id,
                "status": "active",
                "role": {"$in": [ROLE_OWNER, ROLE_ADMIN]},
            }
        )
        if not member:
            raise PermissionError("Insufficient permissions")

    def _require_org_member(self, *, org_id: ObjectId, user_id: ObjectId):
        member = self.org_members.find_one(
            {
                "org_id": org_id,
                "user_id": user_id,
                "status": "active",
            }
        )
        if not member:
            raise PermissionError("User is not an organization member")

    # -----------------------------
    # Department lifecycle
    # -----------------------------

    def create_department(
        self,
        *,
        org_id: str,
        name: str,
        description: str | None,
        actor_id: str,
    ) -> ObjectId:
        org_oid = ObjectId(org_id)
        actor_oid = ObjectId(actor_id)

        self._require_org_admin(org_id=org_oid, user_id=actor_oid)

        if self.departments.find_one(
            {"org_id": org_oid, "name": name.strip(), "is_active": True}
        ):
            raise ValueError("Department already exists")

        dept = Department(
            org_id=org_oid,
            name=name,
            description=description,
            created_by=actor_oid,
        )

        result = self.departments.insert_one(dept.to_dict())

        self.audit.log_event(
            user_id=actor_id,
            org_id=org_id,
            action="department.created",
            resource_type="department",
            resource_id=str(result.inserted_id),
        )

        return result.inserted_id

    def list_departments(self, *, org_id: str, include_inactive: bool = False) -> list:
        query = {"org_id": ObjectId(org_id)}
        if not include_inactive:
            query["is_active"] = True

        return list(self.departments.find(query))

    def update_department(
        self,
        *,
        department_id: str,
        name: str | None,
        description: str | None,
        actor_id: str,
    ):
        dept = self.departments.find_one({"_id": ObjectId(department_id)})
        if not dept:
            raise ValueError("Department not found")

        self._require_org_admin(
            org_id=dept["org_id"],
            user_id=ObjectId(actor_id),
        )

        updates = {"updated_at": datetime.utcnow()}
        if name is not None:
            updates["name"] = name.strip()
        if description is not None:
            updates["description"] = description

        self.departments.update_one(
            {"_id": dept["_id"]},
            {"$set": updates},
        )

        self.audit.log_event(
            user_id=actor_id,
            org_id=str(dept["org_id"]),
            action="department.updated",
            resource_type="department",
            resource_id=department_id,
        )

    def deactivate_department(self, *, department_id: str, actor_id: str):
        dept = self.departments.find_one({"_id": ObjectId(department_id)})
        if not dept:
            raise ValueError("Department not found")

        self._require_org_admin(
            org_id=dept["org_id"],
            user_id=ObjectId(actor_id),
        )

        self.departments.update_one(
            {"_id": dept["_id"]},
            {
                "$set": {
                    "is_active": False,
                    "updated_at": datetime.utcnow(),
                }
            },
        )

        self.audit.log_event(
            user_id=actor_id,
            org_id=str(dept["org_id"]),
            action="department.deactivated",
            resource_type="department",
            resource_id=department_id,
        )

    # -----------------------------
    # Department membership
    # -----------------------------

    def assign_user(
        self,
        *,
        department_id: str,
        user_id: str,
        role: str = DEPT_ROLE_MEMBER,
        actor_id: str,
    ):
        dept = self.departments.find_one({"_id": ObjectId(department_id), "is_active": True})
        if not dept:
            raise ValueError("Department not found or inactive")

        org_oid = dept["org_id"]

        self._require_org_admin(
            org_id=org_oid,
            user_id=ObjectId(actor_id),
        )

        self._require_org_member(
            org_id=org_oid,
            user_id=ObjectId(user_id),
        )

        if self.department_members.find_one(
            {
                "department_id": dept["_id"],
                "user_id": ObjectId(user_id),
                "is_active": True,
            }
        ):
            raise ValueError("User already assigned to department")

        member = DepartmentMember(
            org_id=org_oid,
            department_id=dept["_id"],
            user_id=ObjectId(user_id),
            role=role,
            assigned_by=ObjectId(actor_id),
        )

        self.department_members.insert_one(member.to_dict())

        self.audit.log_event(
            user_id=actor_id,
            org_id=str(org_oid),
            action="department.member.assigned",
            resource_type="department",
            resource_id=department_id,
            metadata={"target_user": user_id, "role": role},
        )

    def change_member_role(
        self,
        *,
        department_id: str,
        user_id: str,
        new_role: str,
        actor_id: str,
    ):
        dept = self.departments.find_one({"_id": ObjectId(department_id)})
        if not dept:
            raise ValueError("Department not found")

        self._require_org_admin(
            org_id=dept["org_id"],
            user_id=ObjectId(actor_id),
        )

        result = self.department_members.update_one(
            {
                "department_id": dept["_id"],
                "user_id": ObjectId(user_id),
                "is_active": True,
            },
            {
                "$set": {
                    "role": new_role,
                    "updated_at": datetime.utcnow(),
                }
            },
        )

        if result.matched_count == 0:
            raise ValueError("Department member not found")

        self.audit.log_event(
            user_id=actor_id,
            org_id=str(dept["org_id"]),
            action="department.member.role_changed",
            resource_type="department",
            resource_id=department_id,
            metadata={"target_user": user_id, "new_role": new_role},
        )

    def remove_user(self, *, department_id: str, user_id: str, actor_id: str):
        dept = self.departments.find_one({"_id": ObjectId(department_id)})
        if not dept:
            raise ValueError("Department not found")

        self._require_org_admin(
            org_id=dept["org_id"],
            user_id=ObjectId(actor_id),
        )

        self.department_members.update_one(
            {
                "department_id": dept["_id"],
                "user_id": ObjectId(user_id),
                "is_active": True,
            },
            {
                "$set": {
                    "is_active": False,
                    "updated_at": datetime.utcnow(),
                }
            },
        )

        self.audit.log_event(
            user_id=actor_id,
            org_id=str(dept["org_id"]),
            action="department.member.removed",
            resource_type="department",
            resource_id=department_id,
            metadata={"target_user": user_id},
        )
