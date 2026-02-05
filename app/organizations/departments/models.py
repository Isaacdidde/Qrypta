from datetime import datetime
from bson import ObjectId


# ==================================================
# DEPARTMENT
# ==================================================

class Department:
    """
    Represents a department inside an organization.
    Example: IT, HR, Finance, Marketing
    """

    def __init__(
        self,
        *,
        org_id: ObjectId,
        name: str,
        description: str | None = None,
        is_active: bool = True,
        created_by: ObjectId,
    ):
        self.org_id = org_id
        self.name = name.strip()
        self.description = description
        self.is_active = is_active

        self.created_by = created_by
        self.created_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()

    def to_dict(self) -> dict:
        return {
            "org_id": self.org_id,
            "name": self.name,
            "description": self.description,
            "is_active": self.is_active,
            "created_by": self.created_by,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


# ==================================================
# DEPARTMENT MEMBERSHIP (OPTIONAL BUT POWERFUL)
# ==================================================

class DepartmentMember:
    """
    Explicit mapping between users and departments.

    This allows:
    - Users in multiple departments
    - Department-specific roles later
    """

    def __init__(
        self,
        *,
        org_id: ObjectId,
        department_id: ObjectId,
        user_id: ObjectId,
        role: str = "member",   # member | lead | head
        is_active: bool = True,
        assigned_by: ObjectId,
    ):
        self.org_id = org_id
        self.department_id = department_id
        self.user_id = user_id
        self.role = role
        self.is_active = is_active

        self.assigned_by = assigned_by
        self.assigned_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()

    def to_dict(self) -> dict:
        return {
            "org_id": self.org_id,
            "department_id": self.department_id,
            "user_id": self.user_id,
            "role": self.role,
            "is_active": self.is_active,
            "assigned_by": self.assigned_by,
            "assigned_at": self.assigned_at,
            "updated_at": self.updated_at,
        }
