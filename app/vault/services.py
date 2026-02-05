from bson import ObjectId
from datetime import datetime
from flask import current_app

from app.core.encryption import EncryptionService
from app.core.audit import AuditLogger
from app.core.permissions import PermissionService
from app.users.models import ROLE_PLATFORM_SUPERADMIN
from .models import VaultItem, VaultPermission, VaultSecret


class VaultService:
    """
    SINGLE SOURCE OF TRUTH for vault security, permissions, and audits.
    All dashboards, access pages, and logs depend on this file.
    """

    # ==================================================
    # PERMISSION ORDER
    # ==================================================
    PERMISSION_LEVELS = {
        "read": 1,
        "write": 2,
        "execute": 3,
    }

    def __init__(self, encryption_key: str):
        self.crypto = EncryptionService(encryption_key)
        self.audit = AuditLogger()

    # ==================================================
    # COLLECTIONS
    # ==================================================
    @property
    def vaults(self):
        return current_app.db.vaults

    @property
    def secrets(self):
        return current_app.db.vault_secrets

    @property
    def permissions(self):
        return current_app.db.vault_permissions

    @property
    def org_members(self):
        return current_app.db.organization_members

    # ==================================================
    # INTERNAL HELPERS
    # ==================================================
    def _get_vault(self, vault_id: ObjectId) -> dict:
        vault = self.vaults.find_one({"_id": vault_id})
        if not vault:
            raise ValueError("Vault not found")
        return vault

    def _require_permission(self, actual: str, required: str):
        if self.PERMISSION_LEVELS[actual] < self.PERMISSION_LEVELS[required]:
            raise PermissionError("Insufficient permission")

    def _is_platform_admin(self, user_id: ObjectId) -> bool:
        user = current_app.db.users.find_one({"_id": user_id})
        return bool(user and user.get("role") == ROLE_PLATFORM_SUPERADMIN)

    def _get_org_authority(self, org_id: ObjectId, user_id: ObjectId) -> str | None:
        member = self.org_members.find_one(
            {"org_id": org_id, "user_id": user_id, "status": "active"}
        )
        return member["authority"] if member else None

    # ==================================================
    # PERMISSION RESOLUTION (CRITICAL)
    # ==================================================
    def _get_user_permission(self, vault_id: ObjectId, user_id: ObjectId) -> str:
        vault = self._get_vault(vault_id)

        # PLATFORM SUPERADMIN
        if self._is_platform_admin(user_id):
            return "execute"

        # PERSONAL VAULT
        if vault.get("owner_user_id"):
            if vault["owner_user_id"] == user_id:
                return "execute"
            raise PermissionError("Access denied")

        # BUSINESS VAULT
        authority = self._get_org_authority(vault["org_id"], user_id)

        if authority in ("owner", "admin"):
            return "execute"

        perm = self.permissions.find_one(
            {"vault_id": vault_id, "user_id": user_id}
        )
        if not perm:
            raise PermissionError("Access denied")

        return perm["permission"]

    # ==================================================
    # AUDIT WRAPPER
    # ==================================================
    def _audit(self, *, user_id, vault, action, resource_type, resource_id, metadata=None):
        self.audit.log_event(
            user_id=user_id,
            org_id = str(getattr(vault, "org_id", None)) if getattr(vault, "org_id", None) else None,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            metadata=metadata or {},
        )

    # ==================================================
    # VAULT CREATION
    # ==================================================
    def create_personal_vault(self, *, user_id: str, name: str) -> ObjectId:
        vault = VaultItem(
            name=name,
            owner_user_id=ObjectId(user_id),
            org_id=None,
            is_shared=False,
        )
        vault_id = self.vaults.insert_one(vault.to_dict()).inserted_id

        self._audit(
            user_id=user_id,
            vault=vault,
            action="vault.created",
            resource_type="vault",
            resource_id=str(vault_id),
        )
        return vault_id

    def create_business_vault(self, *, org_id: str, creator_user_id: str, name: str) -> ObjectId:
        creator_oid = ObjectId(creator_user_id)

        if not self._is_platform_admin(creator_oid):
            if not PermissionService.has_org_permission(
                org_id=org_id,
                user_id=creator_user_id,
                permission="vault.write",
            ):
                raise PermissionError("Not allowed to create vaults")

        vault = VaultItem(
            name=name,
            owner_user_id=None,
            org_id=ObjectId(org_id),
            is_shared=True,
        )
        vault_id = self.vaults.insert_one(vault.to_dict()).inserted_id

        self._audit(
            user_id=creator_user_id,
            vault=vault,
            action="vault.created",
            resource_type="vault",
            resource_id=str(vault_id),
        )
        return vault_id

    # ==================================================
    # VAULT LISTING (DASHBOARDS)
    # ==================================================
    def list_personal_vaults(self, user_id: str) -> list:
        vaults = list(self.vaults.find({"owner_user_id": ObjectId(user_id)}))
        for v in vaults:
            v["access_level"] = "execute"
            v["is_owner"] = True
        return vaults

    def list_business_vaults_for_user(self, user_id: str) -> list:
        user_oid = ObjectId(user_id)

    # vaults user has any permission on
        vault_ids = self.permissions.find(
            {"user_id": user_oid}
        ).distinct("vault_id")

        vaults = list(
            self.vaults.find(
                {"_id": {"$in": vault_ids}, "is_shared": True}
            )
        )

        for v in vaults:
            perm = self._get_user_permission(v["_id"], user_oid)
            v["access_level"] = perm
            v["is_owner"] = False

        return vaults


    def list_business_vaults_for_admin(self, org_id: str, user_id: str) -> list:
        user_oid = ObjectId(user_id)

        vaults = list(
            self.vaults.find(
                {"org_id": ObjectId(org_id), "is_shared": True}
            )
        )

        for v in vaults:
            perm = self._get_user_permission(v["_id"], user_oid)
            v["access_level"] = perm
            v["is_owner"] = False

        return vaults


    def list_org_vaults_with_metadata(self, org_id: str) -> list:
        pipeline = [
            {"$match": {"org_id": ObjectId(org_id), "is_shared": True}},
            {
                "$lookup": {
                    "from": "vault_permissions",
                    "localField": "_id",
                    "foreignField": "vault_id",
                    "as": "permissions",
                }
            },
            {"$addFields": {"access_count": {"$size": "$permissions"}}},
            {"$project": {"permissions": 0}},
            {"$sort": {"created_at": -1}},
        ]

        vaults = list(self.vaults.aggregate(pipeline))
        for v in vaults:
            v["access_level"] = "execute"
            v["is_owner"] = False
        return vaults

    # ==================================================
    # SECRETS
    # ==================================================
    def list_secrets(self, *, vault_id: str, user_id: str) -> list:
        perm = self._get_user_permission(ObjectId(vault_id), ObjectId(user_id))
        self._require_permission(perm, "read")

        return list(
            self.secrets.find(
                {"vault_id": ObjectId(vault_id), "deleted_at": None},
                {"encrypted_value": 0},
            )
        )

    def add_secret(self, *, vault_id: str, user_id: str, name: str, value: str) -> ObjectId:
        vault_oid = ObjectId(vault_id)
        user_oid = ObjectId(user_id)

        vault = self._get_vault(vault_oid)
        perm = self._get_user_permission(vault_oid, user_oid)
        self._require_permission(perm, "write")

        encrypted = self.crypto.encrypt(value)
        secret = VaultSecret(
            vault_id=vault_oid,
            name=name,
            encrypted_value=encrypted,
            created_by=user_oid,
        )
        secret_id = self.secrets.insert_one(secret.to_dict()).inserted_id

        self._audit(
            user_id=user_id,
            vault=vault,
            action="secret.created",
            resource_type="vault_secret",
            resource_id=str(secret_id),
            metadata={"secret_name": name},
        )
        return secret_id

    def read_secret(self, *, secret_id: str, user_id: str) -> str:
        secret = self.secrets.find_one({"_id": ObjectId(secret_id)})
        if not secret or secret.get("deleted_at"):
            raise ValueError("Secret not found")

        vault = self._get_vault(secret["vault_id"])
        perm = self._get_user_permission(secret["vault_id"], ObjectId(user_id))
        self._require_permission(perm, "read")

        self._audit(
            user_id=user_id,
            vault=vault,
            action="secret.read",
            resource_type="vault_secret",
            resource_id=secret_id,
            metadata={"secret_name": secret["name"]},
        )
        return self.crypto.decrypt(secret["encrypted_value"])

    def copy_secret(self, *, secret_id: str, user_id: str) -> str:
        secret = self.secrets.find_one({"_id": ObjectId(secret_id)})
        if not secret:
            raise ValueError("Secret not found")

        vault = self._get_vault(secret["vault_id"])
        perm = self._get_user_permission(secret["vault_id"], ObjectId(user_id))
        self._require_permission(perm, "read")

        self._audit(
            user_id=user_id,
            vault=vault,
            action="secret.copied",
            resource_type="vault_secret",
            resource_id=secret_id,
            metadata={"secret_name": secret["name"]},
        )
        return self.crypto.decrypt(secret["encrypted_value"])

    # ==================================================
    # VAULT PERMISSIONS (OWNER SAFE)
    # ==================================================
    def grant_access(self, *, vault_id: str, user_id: str, permission: str, granted_by: str):
        if permission not in self.PERMISSION_LEVELS:
            raise ValueError("Invalid permission")

        vault_oid = ObjectId(vault_id)
        target_oid = ObjectId(user_id)
        actor_oid = ObjectId(granted_by)

        vault = self._get_vault(vault_oid)

        target_auth = self._get_org_authority(vault["org_id"], target_oid)
        actor_auth = self._get_org_authority(vault["org_id"], actor_oid)

        # ❌ OWNER IS IMMUTABLE
        if target_auth == "owner":
            raise PermissionError("Owner access cannot be modified")

        # ❌ ADMIN CAN ONLY BE MANAGED BY OWNER
        if target_auth == "admin" and actor_auth != "owner":
            raise PermissionError("Only owner can manage admins")

        if actor_auth not in ("owner", "admin") and not self._is_platform_admin(actor_oid):
            raise PermissionError("Insufficient authority")

        self.permissions.update_one(
            {"vault_id": vault_oid, "user_id": target_oid},
            {
                "$set": {
                    "permission": permission,
                    "granted_by": actor_oid,
                    "granted_at": datetime.utcnow(),
                }
            },
            upsert=True,
        )

        self._audit(
            user_id=granted_by,
            vault=vault,
            action="vault.permission.granted",
            resource_type="vault",
            resource_id=vault_id,
            metadata={"target_user_id": user_id, "permission": permission},
        )

    def revoke_access(self, *, vault_id: str, user_id: str, revoked_by: str):
        vault_oid = ObjectId(vault_id)
        target_oid = ObjectId(user_id)
        actor_oid = ObjectId(revoked_by)

        vault = self._get_vault(vault_oid)

        target_auth = self._get_org_authority(vault["org_id"], target_oid)
        actor_auth = self._get_org_authority(vault["org_id"], actor_oid)

        if target_auth == "owner":
            raise PermissionError("Owner access cannot be revoked")

        if target_auth == "admin" and actor_auth != "owner":
            raise PermissionError("Only owner can revoke admin access")

        if actor_auth not in ("owner", "admin") and not self._is_platform_admin(actor_oid):
            raise PermissionError("Insufficient authority")

        self.permissions.delete_one(
            {"vault_id": vault_oid, "user_id": target_oid}
        )

        self._audit(
            user_id=revoked_by,
            vault=vault,
            action="vault.permission.revoked",
            resource_type="vault",
            resource_id=vault_id,
            metadata={"target_user_id": user_id},
        )
