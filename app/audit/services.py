from datetime import datetime
from bson import ObjectId
from flask import current_app


# ==================================================
# WRITE-ONLY AUDIT LOGGER
# ==================================================

class AuditLogger:
    """
    WRITE-ONLY audit logger.

    Rules:
    - Append-only (never update/delete)
    - No sensitive data (no passwords, OTPs, secrets)
    - Fail-safe (audit failure must not break app)
    """

    @property
    def logs(self):
        return current_app.db.audit_logs

    def log_event(
        self,
        *,
        action: str,
        resource_type: str,
        resource_id: str | None = None,
        user_id: str | None = None,
        org_id: str | None = None,
        ip_address: str | None = None,
        metadata: dict | None = None,
    ) -> None:
        try:
            doc = {
                "timestamp": datetime.utcnow(),
                "action": action,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "user_id": ObjectId(user_id) if user_id else None,
                "org_id": ObjectId(org_id) if org_id else None,
                "ip_address": ip_address,
                "metadata": metadata or {},
            }

            self.logs.insert_one(doc)

        except Exception:
            # Auditing must never block the main flow
            pass


# ==================================================
# READ-ONLY AUDIT QUERY SERVICE
# ==================================================

class AuditService:
    """
    READ-ONLY audit query service.

    Visibility rules:
    - Platform Superadmin → all logs (global)
    - Owner / Admin       → all org logs
    - Manager             → department logs only
    - Employee            → no org logs
    """

    DEFAULT_LIMIT = 30
    MAX_EXPORT_LIMIT = 10_000

    # ==================================================
    # COLLECTIONS
    # ==================================================
    @property
    def logs(self):
        return current_app.db.audit_logs

    @property
    def members(self):
        return current_app.db.organization_members

    # ==================================================
    # INTERNAL HELPERS
    # ==================================================
    def _paginate(self, *, page: int, limit: int):
        page = max(page, 1)
        limit = min(max(limit, 1), self.MAX_EXPORT_LIMIT)
        skip = (page - 1) * limit
        return skip, limit

    @staticmethod
    def _sort_order(sort: str):
        return -1 if sort == "desc" else 1

    @staticmethod
    def _empty():
        return {
            "items": [],
            "page": 1,
            "limit": 0,
            "total": 0,
            "pages": 1,
        }

    # ==================================================
    # PLATFORM SUPERADMIN — GLOBAL LOGS
    # ==================================================
    def list_all_logs(
        self,
        *,
        page: int = 1,
        limit: int = DEFAULT_LIMIT,
        filters: dict | None = None,
        sort: str = "desc",
        export: bool = False,
    ) -> dict:

        filters = filters or {}
        match = {}

        if filters.get("action"):
            match["action"] = filters["action"]

        if filters.get("resource_type"):
            match["resource_type"] = filters["resource_type"]

        sort_order = self._sort_order(sort)

        if export:
            skip = 0
            limit = self.MAX_EXPORT_LIMIT
            page = 1
        else:
            skip, limit = self._paginate(page=page, limit=limit)

        pipeline = [
            {"$match": match},
            {"$sort": {"timestamp": sort_order}},
            {"$skip": skip},
            {"$limit": limit},
            {
                "$lookup": {
                    "from": "users",
                    "localField": "user_id",
                    "foreignField": "_id",
                    "as": "user",
                }
            },
            {"$unwind": {"path": "$user", "preserveNullAndEmptyArrays": True}},
            {
                "$project": {
                    "_id": 1,
                    "timestamp": 1,
                    "action": 1,
                    "resource_type": 1,
                    "resource_id": 1,
                    "ip_address": 1,
                    "metadata": 1,
                    "org_id": 1,
                    "actor": {"$ifNull": ["$user.email", "System"]},
                }
            },
        ]

        items = list(self.logs.aggregate(pipeline))
        total = self.logs.count_documents(match)
        pages = 1 if export else max(1, (total + limit - 1) // limit)

        return {
            "items": items,
            "page": page,
            "limit": limit,
            "total": total,
            "pages": pages,
        }

    # ==================================================
    # ORG LOGS (OWNER / ADMIN / MANAGER)
    # ==================================================
    def list_org_logs(
        self,
        *,
        org_id: str,
        actor_id: str,
        page: int = 1,
        limit: int = DEFAULT_LIMIT,
        filters: dict | None = None,
        sort: str = "desc",
        export: bool = False,
    ) -> dict:

        filters = filters or {}
        actor_oid = ObjectId(actor_id)
        org_oid = ObjectId(org_id)

        actor_member = self.members.find_one(
            {
                "org_id": org_oid,
                "user_id": actor_oid,
                "status": "active",
            }
        )

        if not actor_member:
            return self._empty()

        authority = actor_member.get("authority")
        role = actor_member.get("role")
        department = actor_member.get("department")

        match = {"org_id": org_oid}

        if filters.get("action"):
            match["action"] = filters["action"]

        if filters.get("resource_type"):
            match["resource_type"] = filters["resource_type"]

        # MANAGER → department scoped
        if authority == "member" and role == "manager":
            if not department:
                return self._empty()

            dept_user_ids = self.members.distinct(
                "user_id",
                {
                    "org_id": org_oid,
                    "department": department,
                    "status": "active",
                },
            )

            if not dept_user_ids:
                return self._empty()

            match["user_id"] = {"$in": dept_user_ids}

        # EMPLOYEE → no access
        elif authority == "member":
            return self._empty()

        # OWNER / ADMIN → full org access

        sort_order = self._sort_order(sort)

        if export:
            skip = 0
            limit = self.MAX_EXPORT_LIMIT
            page = 1
        else:
            skip, limit = self._paginate(page=page, limit=limit)

        pipeline = [
            {"$match": match},
            {"$sort": {"timestamp": sort_order}},
            {"$skip": skip},
            {"$limit": limit},
            {
                "$lookup": {
                    "from": "users",
                    "localField": "user_id",
                    "foreignField": "_id",
                    "as": "user",
                }
            },
            {"$unwind": {"path": "$user", "preserveNullAndEmptyArrays": True}},
            {
                "$project": {
                    "_id": 1,
                    "timestamp": 1,
                    "action": 1,
                    "resource_type": 1,
                    "resource_id": 1,
                    "ip_address": 1,
                    "metadata": 1,
                    "actor": {"$ifNull": ["$user.email", "System"]},
                }
            },
        ]

        items = list(self.logs.aggregate(pipeline))
        total = self.logs.count_documents(match)
        pages = 1 if export else max(1, (total + limit - 1) // limit)

        return {
            "items": items,
            "page": page,
            "limit": limit,
            "total": total,
            "pages": pages,
        }

    # ==================================================
    # USER LOGS (SELF)
    # ==================================================
    def list_user_logs(
        self,
        *,
        user_id: str,
        page: int = 1,
        limit: int = DEFAULT_LIMIT,
        sort: str = "desc",
    ) -> dict:

        match = {"user_id": ObjectId(user_id)}
        sort_order = self._sort_order(sort)
        skip, limit = self._paginate(page=page, limit=limit)

        pipeline = [
            {"$match": match},
            {"$sort": {"timestamp": sort_order}},
            {"$skip": skip},
            {"$limit": limit},
            {
                "$project": {
                    "_id": 1,
                    "timestamp": 1,
                    "action": 1,
                    "resource_type": 1,
                    "resource_id": 1,
                    "metadata": 1,
                    "ip_address": 1,
                }
            },
        ]

        items = list(self.logs.aggregate(pipeline))
        total = self.logs.count_documents(match)

        return {
            "items": items,
            "page": page,
            "limit": limit,
            "total": total,
            "pages": max(1, (total + limit - 1) // limit),
        }
