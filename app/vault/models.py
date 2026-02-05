from datetime import datetime
from bson import ObjectId


# ==================================================
# VAULT (CONTAINER)
# ==================================================
class VaultItem:
    """
    Represents a vault container.
    Can be personal or business.
    """

    def __init__(
        self,
        *,
        name: str,
        encrypted_payload: str | None = None,
        owner_user_id: ObjectId | None = None,
        org_id: ObjectId | None = None,
        is_shared: bool = False,
    ):
        self.name = name

        # NOTE:
        # encrypted_payload is kept ONLY for backward compatibility.
        # New secrets live in VaultSecret.
        self.encrypted_payload = encrypted_payload

        # Ownership
        self.owner_user_id = owner_user_id  # personal vault owner
        self.org_id = org_id                # business vault owner

        self.is_shared = is_shared
        self.created_at = datetime.utcnow()

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "encrypted_payload": self.encrypted_payload,
            "owner_user_id": self.owner_user_id,
            "org_id": self.org_id,
            "is_shared": self.is_shared,
            "created_at": self.created_at,
        }

    @staticmethod
    def from_dict(data: dict) -> "VaultItem":
        item = VaultItem(
            name=data["name"],
            encrypted_payload=data.get("encrypted_payload"),
            owner_user_id=data.get("owner_user_id"),
            org_id=data.get("org_id"),
            is_shared=data.get("is_shared", False),
        )
        item.created_at = data.get("created_at", datetime.utcnow())
        return item


# ==================================================
# VAULT SECRET (ITEM INSIDE VAULT)
# ==================================================
class VaultSecret:
    """
    Individual secret stored inside a vault.
    """

    def __init__(
        self,
        *,
        vault_id: ObjectId,
        name: str,
        encrypted_value: str,
        created_by: ObjectId,
    ):
        self.vault_id = vault_id
        self.name = name
        self.encrypted_value = encrypted_value
        self.created_by = created_by
        self.created_at = datetime.utcnow()

    def to_dict(self) -> dict:
        return {
            "vault_id": self.vault_id,
            "name": self.name,
            "encrypted_value": self.encrypted_value,
            "created_by": self.created_by,
            "created_at": self.created_at,
        }

    @staticmethod
    def from_dict(data: dict) -> "VaultSecret":
        secret = VaultSecret(
            vault_id=data["vault_id"],
            name=data["name"],
            encrypted_value=data["encrypted_value"],
            created_by=data["created_by"],
        )
        secret.created_at = data.get("created_at", datetime.utcnow())
        return secret


# ==================================================
# VAULT PERMISSION
# ==================================================
class VaultPermission:
    """
    Represents user-level access to a vault.
    Permissions apply to ALL secrets in the vault.
    """

    def __init__(
        self,
        *,
        vault_id: ObjectId,
        user_id: ObjectId,
        permission: str = "read",  # read | write
        granted_by: ObjectId | None = None,
    ):
        self.vault_id = vault_id
        self.user_id = user_id
        self.permission = permission
        self.granted_by = granted_by
        self.granted_at = datetime.utcnow()

    def to_dict(self) -> dict:
        return {
            "vault_id": self.vault_id,
            "user_id": self.user_id,
            "permission": self.permission,
            "granted_by": self.granted_by,
            "granted_at": self.granted_at,
        }
