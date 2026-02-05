# app/core/permissions.py

from functools import wraps
from bson import ObjectId
from flask import current_app, abort
from flask_login import current_user

from app.users.models import ROLE_PLATFORM_SUPERADMIN


# ==================================================
# AUTHORITY LEVELS (ORG-SCOPED)
# ==================================================

AUTH_OWNER = "owner"      # Organization Owner
AUTH_ADMIN = "admin"      # Organization Admin
AUTH_MEMBER = "member"    # Manager / Employee


# ==================================================
# ORG-LEVEL PERMISSIONS MATRIX (BSON SAFE)
# ==================================================

ORG_PERMISSIONS = {

    # Organization governance
    "org.view": (AUTH_OWNER, AUTH_ADMIN),
    "org.manage": (AUTH_OWNER,),
    "org.invite": (AUTH_OWNER, AUTH_ADMIN),

    # Member management
    "org.remove_member": (AUTH_OWNER,),
    "org.assign_admin": (AUTH_OWNER,),
    "org.view_members": (AUTH_OWNER, AUTH_ADMIN),

    # Vault permissions
    "vault.read": (AUTH_OWNER, AUTH_ADMIN, AUTH_MEMBER),
    "vault.write": (AUTH_OWNER, AUTH_ADMIN),
    "vault.delete": (AUTH_OWNER,),
    "vault.approve_delete": (AUTH_OWNER,),

    # Audit logs (FIXED)
    "audit.view": (AUTH_OWNER, AUTH_ADMIN),
}


# ==================================================
# PERMISSION SERVICE
# ==================================================

class PermissionService:
    """
    Centralized permission evaluation.

    Rules:
    - Platform superadmin bypasses all org checks
    - Org authority controls tenant-scoped access
    """

    # -----------------------------
    # PLATFORM AUTHORITY
    # -----------------------------

    @staticmethod
    def is_platform_admin(user) -> bool:
        return bool(user and user.role == ROLE_PLATFORM_SUPERADMIN)

    # -----------------------------
    # CORE ORG PERMISSION CHECK
    # -----------------------------

    @staticmethod
    def has_org_permission(*, org_id: str | None, user_id: str, permission: str) -> bool:

        # PLATFORM SUPERADMIN BYPASS
        if PermissionService.is_platform_admin(current_user):
            return True

        if not org_id:
            return False

        allowed = ORG_PERMISSIONS.get(permission)
        if not allowed:
            return False

        try:
            org_oid = ObjectId(org_id)
            user_oid = ObjectId(user_id)
        except Exception:
            return False

        member = current_app.db.organization_members.find_one(
            {
                "org_id": org_oid,
                "user_id": user_oid,
                "status": "active",
            }
        )

        if not member:
            return False

        authority = member.get("authority", AUTH_MEMBER)
        return authority in allowed

    # -----------------------------
    # AUTHORITY HELPERS
    # -----------------------------

    @staticmethod
    def is_owner(org_id: str | None, user_id: str) -> bool:
        if PermissionService.is_platform_admin(current_user):
            return True

        if not org_id:
            return False

        try:
            org_oid = ObjectId(org_id)
            user_oid = ObjectId(user_id)
        except Exception:
            return False

        member = current_app.db.organization_members.find_one(
            {
                "org_id": org_oid,
                "user_id": user_oid,
                "status": "active",
            }
        )

        return bool(member and member.get("authority") == AUTH_OWNER)

    @staticmethod
    def is_admin(org_id: str | None, user_id: str) -> bool:
        if PermissionService.is_platform_admin(current_user):
            return True

        if not org_id:
            return False

        try:
            org_oid = ObjectId(org_id)
            user_oid = ObjectId(user_id)
        except Exception:
            return False

        member = current_app.db.organization_members.find_one(
            {
                "org_id": org_oid,
                "user_id": user_oid,
                "status": "active",
            }
        )

        return bool(
            member and member.get("authority") in (AUTH_OWNER, AUTH_ADMIN)
        )

    @staticmethod
    def is_manager(org_id: str | None, user_id: str) -> bool:
        """
        Manager = member authority + manager role
        """
        if PermissionService.is_platform_admin(current_user):
            return True

        if not org_id:
            return False

        try:
            org_oid = ObjectId(org_id)
            user_oid = ObjectId(user_id)
        except Exception:
            return False

        member = current_app.db.organization_members.find_one(
            {
                "org_id": org_oid,
                "user_id": user_oid,
                "status": "active",
            }
        )

        return bool(
            member
            and member.get("authority") == AUTH_MEMBER
            and member.get("role") == "manager"
        )


# ==================================================
# FLASK ROUTE DECORATOR
# ==================================================

def require_org_permission(permission: str):
    """
    Flask route decorator.

    - Requires authentication
    - Uses org_id from URL OR current_user
    """

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)

            # PLATFORM ADMIN BYPASS
            if PermissionService.is_platform_admin(current_user):
                return fn(*args, **kwargs)

            # Prefer route org_id, fallback to user org
            org_id = kwargs.get("org_id") or current_user.organization_id
            if not org_id:
                abort(400, "Organization context missing")

            if not PermissionService.has_org_permission(
                org_id=str(org_id),
                user_id=str(current_user.id),
                permission=permission,
            ):
                abort(403, "Permission denied")

            return fn(*args, **kwargs)

        return wrapper

    return decorator
