# app/admin/routes.py

from flask import render_template, redirect, url_for, flash
from flask_login import login_required, current_user

from . import admin_bp
from .services import AdminService
from app.users.models import ROLE_PLATFORM_SUPERADMIN


# ==================================================
# PLATFORM SUPERADMIN GUARD
# ==================================================

def require_platform_superadmin():
    """
    Hard guard for platform-level administration.
    """
    if (
        not current_user.is_authenticated
        or getattr(current_user, "role", None) != ROLE_PLATFORM_SUPERADMIN
    ):
        flash("Access denied", "danger")
        return False
    return True


# ==================================================
# PLATFORM ADMIN DASHBOARD
# ==================================================

@admin_bp.route("/dashboard")
@login_required
def dashboard():
    if not require_platform_superadmin():
        return redirect(url_for("vault.dashboard"))

    service = AdminService()

    stats = service.get_system_stats()
    users = service.list_users()
    orgs = service.list_organizations()

    return render_template(
        "admin/admin_dashboard.html",
        stats=stats,
        users=users,
        orgs=orgs,
    )


# ==================================================
# USER MANAGEMENT
# ==================================================

@admin_bp.route("/user/suspend/<user_id>")
@login_required
def suspend_user(user_id):
    if not require_platform_superadmin():
        return redirect(url_for("admin.dashboard"))

    service = AdminService()
    service.suspend_user(
        user_id=user_id,
        admin_id=str(current_user.id),
    )

    flash("User suspended", "info")
    return redirect(url_for("admin.dashboard"))


@admin_bp.route("/user/resume/<user_id>")
@login_required
def resume_user(user_id):
    if not require_platform_superadmin():
        return redirect(url_for("admin.dashboard"))

    service = AdminService()
    service.resume_user(
        user_id=user_id,
        admin_id=str(current_user.id),
    )

    flash("User resumed", "success")
    return redirect(url_for("admin.dashboard"))


# ==================================================
# ORGANIZATION MANAGEMENT
# ==================================================

@admin_bp.route("/org/suspend/<org_id>")
@login_required
def suspend_org(org_id):
    if not require_platform_superadmin():
        return redirect(url_for("admin.dashboard"))

    service = AdminService()
    service.suspend_organization(
        org_id=org_id,
        admin_id=str(current_user.id),
    )

    flash("Organization suspended", "warning")
    return redirect(url_for("admin.dashboard"))
