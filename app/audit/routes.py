from flask import (
    render_template,
    flash,
    redirect,
    url_for,
    request,
    Response,
    current_app,
)
from flask_login import login_required, current_user
from bson import ObjectId

from . import audit_bp
from .services import AuditService
from app.core.permissions import PermissionService
from app.users.models import ROLE_PLATFORM_SUPERADMIN


# ==================================================
# PLATFORM HELPER
# ==================================================

def is_platform_admin() -> bool:
    return (
        current_user.is_authenticated
        and current_user.role == ROLE_PLATFORM_SUPERADMIN
    )


# ==================================================
# ORGANIZATION / PLATFORM AUDIT LOGS
# ==================================================

@audit_bp.route("/organization")
@login_required
def org_audit_logs():
    service = AuditService()

    # ==================================================
    # PLATFORM SUPERADMIN — GLOBAL AUDIT VIEW
    # ==================================================
    if is_platform_admin():
        page = request.args.get("page", 1, type=int)
        sort = request.args.get("sort", "desc")
        action = request.args.get("action")
        resource_type = request.args.get("resource_type")
        export = request.args.get("export") == "csv"

        filters = {
            "action": action,
            "resource_type": resource_type,
        }

        result = service.list_all_logs(
            page=page,
            limit=50,
            sort=sort,
            filters=filters,
            export=export,
        )

        if export:
            return _export_audit_csv(result["items"])

        return render_template(
            "dashboard/audit_logs.html",
            logs=result["items"],
            page=result["page"],
            pages=result["pages"],
            total=result["total"],
            sort=sort,
            filters=filters,
            scope="platform",
            is_manager=False,
        )

    # ==================================================
    # BUSINESS / ORG AUDIT VIEW
    # ==================================================

    if (
        current_user.account_type != "business"
        or not current_user.organization_id
    ):
        flash("Access denied", "danger")
        return redirect(url_for("vault.dashboard"))

    org_id = str(current_user.organization_id)
    user_id = str(current_user.id)

    if not PermissionService.has_org_permission(
        org_id=org_id,
        user_id=user_id,
        permission="audit.view",
    ):
        flash("Access denied", "danger")
        return redirect(url_for("vault.dashboard"))

    member = current_app.db.organization_members.find_one(
        {
            "org_id": ObjectId(org_id),
            "user_id": ObjectId(user_id),
            "status": "active",
        }
    )

    # UI-only flag (authorization enforced in service)
    is_manager = bool(
        member
        and member.get("authority") == "member"
        and member.get("role") == "manager"
    )

    page = request.args.get("page", 1, type=int)
    sort = request.args.get("sort", "desc")
    action = request.args.get("action")
    resource_type = request.args.get("resource_type")
    export = request.args.get("export") == "csv"

    filters = {
        "action": action,
        "resource_type": resource_type,
    }

    result = service.list_org_logs(
        org_id=org_id,
        actor_id=user_id,
        page=page,
        limit=30,
        sort=sort,
        filters=filters,
        export=export,
    )

    if export:
        return _export_audit_csv(result["items"])

    return render_template(
        "dashboard/audit_logs.html",
        logs=result["items"],
        page=result["page"],
        pages=result["pages"],
        total=result["total"],
        sort=sort,
        filters=filters,
        scope="organization",
        is_manager=is_manager,
    )


# ==================================================
# USER AUDIT LOGS (SELF)
# ==================================================

@audit_bp.route("/me")
@login_required
def my_audit_logs():
    service = AuditService()

    page = request.args.get("page", 1, type=int)
    sort = request.args.get("sort", "desc")

    result = service.list_user_logs(
        user_id=str(current_user.id),
        page=page,
        limit=30,
        sort=sort,
    )

    return render_template(
        "dashboard/audit_logs.html",
        logs=result["items"],
        page=result["page"],
        pages=result["pages"],
        total=result["total"],
        sort=sort,
        filters={},
        scope="self",
        is_manager=False,
    )


# ==================================================
# CSV EXPORT
# ==================================================

def _export_audit_csv(items: list):
    """
    Stream audit logs as CSV.
    """

    def esc(val):
        if val is None:
            return ""
        return str(val).replace('"', '""')

    def generate():
        yield '"Time","Actor","Action","Resource Type","Resource ID","IP","Details"\n'

        for log in items:
            yield (
                f"\"{esc(log.get('timestamp'))}\","
                f"\"{esc(log.get('actor'))}\","
                f"\"{esc(log.get('action'))}\","
                f"\"{esc(log.get('resource_type'))}\","
                f"\"{esc(log.get('resource_id'))}\","
                f"\"{esc(log.get('ip_address'))}\","
                f"\"{esc(log.get('metadata'))}\"\n"
            )

    return Response(
        generate(),
        mimetype="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=audit_logs.csv"
        },
    )
