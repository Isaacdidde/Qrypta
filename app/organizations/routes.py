from bson import ObjectId
from flask import (
    render_template,
    request,
    redirect,
    url_for,
    flash,
    current_app,
    abort,
    session,
)
from flask_login import login_required, current_user

from . import organizations_bp
from .services import OrganizationService
from app.organizations.invitations.services import InvitationService
from app.vault.services import VaultService
from app.core.permissions import PermissionService
from app.users.models import ROLE_PLATFORM_SUPERADMIN


# ==================================================
# PLATFORM HELPERS
# ==================================================

def is_platform_admin() -> bool:
    return (
        current_user.is_authenticated
        and current_user.role == ROLE_PLATFORM_SUPERADMIN
    )


# ==================================================
# BUSINESS HELPERS
# ==================================================

def is_business_user() -> bool:
    return (
        current_user.is_authenticated
        and current_user.account_type == "business"
    )


def has_organization() -> bool:
    return bool(current_user.organization_id)


def is_business_owner() -> bool:
    if not (is_business_user() and has_organization()):
        return False
    return PermissionService.is_owner(
        org_id=str(current_user.organization_id),
        user_id=str(current_user.id),
    )


def is_business_admin() -> bool:
    if not (is_business_user() and has_organization()):
        return False
    return PermissionService.is_admin(
        org_id=str(current_user.organization_id),
        user_id=str(current_user.id),
    )


def is_business_manager() -> bool:
    if not (is_business_user() and has_organization()):
        return False

    member = current_app.db.organization_members.find_one(
        {
            "org_id": ObjectId(current_user.organization_id),
            "user_id": ObjectId(current_user.id),
            "status": "active",
        }
    )
    return bool(member and member.get("role") == "manager")


def current_department():
    if not (is_business_user() and has_organization()):
        return None

    member = current_app.db.organization_members.find_one(
        {
            "org_id": ObjectId(current_user.organization_id),
            "user_id": ObjectId(current_user.id),
            "status": "active",
        }
    )
    return member.get("department") if member else None


def org_id() -> str:
    return str(current_user.organization_id)


# ==================================================
# ORGANIZATION SETUP (FIRST LOGIN – OWNER)
# ==================================================

@organizations_bp.route("/setup", methods=["GET", "POST"])
@login_required
def setup():
    """
    First-time organization creation for business owners.
    """

    if current_user.account_type != "business":
        abort(403)

    if current_user.organization_id:
        return redirect(url_for("organizations.dashboard"))

    # Block invited users from creating org
    pending_invite = current_app.db.organization_invitations.find_one(
        {
            "email": current_user.email.lower(),
            "status": "invited",
        }
    )
    if pending_invite:
        flash("Please accept your invitation to continue.", "info")
        return redirect(url_for("vault.dashboard"))

    if request.method == "POST":
        name = request.form.get("organization_name", "").strip()
        if not name:
            flash("Organization name is required.", "danger")
            return redirect(request.url)

        OrganizationService().create_organization(
            name=name,
            owner_id=str(current_user.id),
        )

        flash("Organization created successfully.", "success")
        return redirect(url_for("organizations.dashboard"))

    return render_template("organizations/setup.html")


# ==================================================
# DASHBOARD
# ==================================================

@organizations_bp.route("/dashboard")
@login_required
def dashboard():
    # -----------------------------
    # Platform admin
    # -----------------------------
    if is_platform_admin():
        organizations = OrganizationService().list_organizations()
        return render_template(
            "dashboard/platform_dashboard.html",
            organizations=organizations,
            is_platform_admin=True,
        )

    # -----------------------------
    # Business user without org
    # -----------------------------
    if is_business_user() and not has_organization():
        return redirect(url_for("organizations.setup"))

    # -----------------------------
    # Non-business users
    # -----------------------------
    if not is_business_user():
        return redirect(url_for("vault.dashboard"))

    org_service = OrganizationService()
    vault_service = VaultService(
        encryption_key=current_app.config["ENCRYPTION_KEY"]
    )

    sort = request.args.get("sort", "new")
    role_filter = request.args.get("role")
    dept_filter = request.args.get("department")

    # -----------------------------
    # Members visibility
    # -----------------------------
    if is_business_owner() or is_business_admin():
        members = org_service.list_members(
            org_id(),
            role=role_filter,
            department=dept_filter,
            sort=sort,
        )
    elif is_business_manager():
        members = org_service.list_members(
            org_id(),
            role=role_filter,
            department=current_department(),
            sort=sort,
        )
    else:
        members = [
            m
            for m in org_service.list_members(org_id(), sort=sort)
            if str(m["user_id"]) == str(current_user.id)
        ]

    # -----------------------------
    # Vault visibility
    # -----------------------------
    if is_business_owner() or is_business_admin():
        vaults = vault_service.list_org_vaults_with_metadata(org_id())
    else:
        vaults = vault_service.list_business_vaults_for_user(
            str(current_user.id)
        )

    return render_template(
        "dashboard/business_dashboard.html",
        organization=org_service.get_organization(org_id()),
        members=members,
        vaults=vaults,
        is_owner=is_business_owner(),
        is_admin=is_business_admin(),
        is_manager=is_business_manager(),
        sort=sort,
        role_filter=role_filter,
        department_filter=dept_filter,
    )


# ==================================================
# INVITATIONS
# ==================================================

@organizations_bp.route("/invite", methods=["GET", "POST"])
@login_required
def invite_member():
    if not (is_business_owner() or is_business_admin()):
        abort(403)

    if request.method == "POST":
        InvitationService().invite(
            org_id=org_id(),
            email=request.form["email"],
            role=request.form["role"],
            department=request.form.get("department"),
            invited_by=str(current_user.id),
        )
        flash("Invitation sent successfully.", "success")
        return redirect(url_for("organizations.dashboard"))

    return render_template("dashboard/org_invite.html")


# ==================================================
# MEMBER MANAGEMENT
# ==================================================

@organizations_bp.route("/authority/admin/<user_id>", methods=["POST"])
@login_required
def grant_admin(user_id):
    if not is_business_owner():
        abort(403)

    OrganizationService().set_authority(
        org_id=org_id(),
        user_id=user_id,
        new_authority="admin",
        actor_id=str(current_user.id),
    )
    flash("Admin privileges granted.", "success")
    return redirect(url_for("organizations.dashboard"))


@organizations_bp.route("/authority/member/<user_id>", methods=["POST"])
@login_required
def revoke_admin(user_id):
    if not is_business_owner():
        abort(403)

    OrganizationService().set_authority(
        org_id=org_id(),
        user_id=user_id,
        new_authority="member",
        actor_id=str(current_user.id),
    )
    flash("Admin privileges revoked.", "info")
    return redirect(url_for("organizations.dashboard"))


@organizations_bp.route("/suspend/<user_id>", methods=["POST"])
@login_required
def suspend_member(user_id):
    if not is_business_admin():
        abort(403)

    OrganizationService().suspend_member(
        org_id=org_id(),
        user_id=user_id,
        actor_id=str(current_user.id),
    )
    flash("Member suspended.", "warning")
    return redirect(url_for("organizations.dashboard"))


@organizations_bp.route("/reactivate/<user_id>", methods=["POST"])
@login_required
def reactivate_member(user_id):
    if not is_business_admin():
        abort(403)

    OrganizationService().reactivate_member(
        org_id=org_id(),
        user_id=user_id,
        actor_id=str(current_user.id),
    )
    flash("Member reactivated.", "success")
    return redirect(url_for("organizations.dashboard"))


@organizations_bp.route("/remove/<user_id>", methods=["POST"])
@login_required
def remove_member(user_id):
    if not is_business_owner():
        abort(403)

    OrganizationService().remove_member(
        org_id=org_id(),
        user_id=user_id,
        actor_id=str(current_user.id),
    )
    flash("Member removed.", "info")
    return redirect(url_for("organizations.dashboard"))


# ==================================================
# INVITATION ACCEPTANCE
# ==================================================

@organizations_bp.route("/accept/<token>")
def accept_invitation(token):
    if not current_user.is_authenticated:
        session["pending_invite_token"] = token
        return redirect(url_for("auth.login"))

    return _finalize_invite(token)


def _finalize_invite(token: str):
    try:
        InvitationService().accept(
            token=token,
            user_id=str(current_user.id),
        )
        flash("You have successfully joined the organization.", "success")
        return redirect(url_for("organizations.dashboard"))
    except Exception:
        current_app.logger.exception("Invitation acceptance failed")
        flash("Invalid or expired invitation link.", "danger")
        return redirect(url_for("vault.dashboard"))
