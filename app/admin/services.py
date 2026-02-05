from bson import ObjectId
from flask import current_app

from .models import AdminActionLog


class AdminService:
    """
    Handles super-admin operations.
    """

    # -----------------------------
    # Collection helpers
    # -----------------------------
    @property
    def users(self):
        return current_app.db.users

    @property
    def orgs(self):
        return current_app.db.organizations

    @property
    def admin_logs(self):
        return current_app.db.admin_logs

    # -----------------------------
    # Metrics
    # -----------------------------
    def get_system_stats(self) -> dict:
        return {
            "total_users": self.users.count_documents({}),
            "total_organizations": self.orgs.count_documents({}),
            "active_users": self.users.count_documents({"is_active": True}),
        }

    # -----------------------------
    # User Management
    # -----------------------------
    def list_users(self) -> list:
        return list(
            self.users.find(
                {},
                {
                    "email": 1,
                    "role": 1,
                    "is_active": 1,
                    "last_login": 1,
                },
            )
        )

    def suspend_user(self, *, user_id: str, admin_id: str):
        self.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"is_active": False}},
        )

        self._log_action(
            admin_id=admin_id,
            action="suspend_user",
            target_type="user",
            target_id=user_id,
        )

    def resume_user(self, *, user_id: str, admin_id: str):
        self.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"is_active": True}},
        )

        self._log_action(
            admin_id=admin_id,
            action="resume_user",
            target_type="user",
            target_id=user_id,
        )

    # -----------------------------
    # Organization Management
    # -----------------------------
    def list_organizations(self) -> list:
        return list(
            self.orgs.find(
                {},
                {
                    "name": 1,
                    "is_active": 1,
                    "created_at": 1,
                },
            )
        )

    def suspend_organization(self, *, org_id: str, admin_id: str):
        self.orgs.update_one(
            {"_id": ObjectId(org_id)},
            {"$set": {"is_active": False}},
        )

        self._log_action(
            admin_id=admin_id,
            action="suspend_organization",
            target_type="organization",
            target_id=org_id,
        )

    # -----------------------------
    # Internal audit logging
    # -----------------------------
    def _log_action(
        self,
        *,
        admin_id: str,
        action: str,
        target_type: str,
        target_id: str,
    ):
        log = AdminActionLog(
            admin_id=admin_id,
            action=action,
            target_type=target_type,
            target_id=target_id,
        )
        self.admin_logs.insert_one(log.to_dict())
