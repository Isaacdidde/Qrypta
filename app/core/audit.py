# app/core/audit.py

from datetime import datetime
from bson import ObjectId, errors as bson_errors
from flask import current_app, request


class AuditLogger:
    """
    Records security-relevant events.

    Design principles:
    - Write-only
    - Immutable
    - No permission logic
    - Must NEVER raise exceptions
    """

    # -------------------------------------------------
    # Collection accessor
    # -------------------------------------------------
    @property
    def collection(self):
        return current_app.db.audit_logs

    # -------------------------------------------------
    # Public API
    # -------------------------------------------------
    def log_event(
        self,
        *,
        user_id: str | None,
        action: str,
        resource_type: str | None = None,
        resource_id: str | None = None,
        org_id: str | None = None,
        metadata: dict | None = None,
    ) -> None:
        """
        Write a single immutable audit event.

        HARD RULE:
        - This method must NEVER crash the app.
        """

        try:
            event = {
                # -----------------------------------------
                # Actor / scope
                # -----------------------------------------
                "user_id": self._safe_object_id(user_id),
                "org_id": self._safe_object_id(org_id),

                # -----------------------------------------
                # Action
                # -----------------------------------------
                "action": action,
                "resource_type": resource_type,
                "resource_id": self._normalize_resource_id(resource_id),

                # -----------------------------------------
                # Context
                # -----------------------------------------
                "ip_address": self._get_ip_address(),
                "metadata": metadata or {},

                # -----------------------------------------
                # Timestamp
                # -----------------------------------------
                "timestamp": datetime.utcnow(),
            }

            self.collection.insert_one(event)

        except Exception:
            # 🔒 ABSOLUTE LAST LINE OF DEFENSE
            # Audit logging must NEVER break auth / business flows
            try:
                current_app.logger.exception("Audit logging failed")
            except Exception:
                pass

    # -------------------------------------------------
    # Helpers
    # -------------------------------------------------
    @staticmethod
    def _safe_object_id(value: str | None):
        """
        Convert string → ObjectId safely.

        Rules:
        - None → None
        - Invalid string → None
        - Valid ObjectId → ObjectId
        """
        if not value:
            return None

        try:
            return ObjectId(value)
        except (bson_errors.InvalidId, TypeError, ValueError):
            return None

    @staticmethod
    def _normalize_resource_id(value):
        """
        Normalize resource_id:
        - Valid ObjectId string → ObjectId
        - Invalid string → stored as string
        - None → None
        """
        if not value:
            return None

        try:
            return ObjectId(value)
        except (bson_errors.InvalidId, TypeError, ValueError):
            return value

    @staticmethod
    def _get_ip_address() -> str | None:
        """
        Safely extract client IP.

        Works:
        - Reverse proxies
        - Background jobs
        - CLI / shell
        """
        try:
            forwarded = request.headers.get("X-Forwarded-For")
            if forwarded:
                return forwarded.split(",")[0].strip()

            return request.remote_addr
        except RuntimeError:
            # No request context
            return None
