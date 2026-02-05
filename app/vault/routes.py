from bson import ObjectId
from flask import (
    render_template,
    request,
    redirect,
    url_for,
    flash,
    current_app,
    jsonify,
)
from flask_login import login_required, current_user

from . import vault_bp
from .services import VaultService
from app.organizations.services import OrganizationService
from app.core.permissions import PermissionService
from app.users.models import ROLE_PLATFORM_SUPERADMIN


# ==================================================
# HELPERS
# ==================================================
def is_platform_admin() -> bool:
    return (
        current_user.is_authenticated
        and current_user.role == ROLE_PLATFORM_SUPERADMIN
    )


def vault_service() -> VaultService:
    return VaultService(
        encryption_key=current_app.config["ENCRYPTION_KEY"]
    )


# ==================================================
# VAULT DASHBOARD
# ==================================================
@vault_bp.route("/")
@login_required
def dashboard():
    service = vault_service()

    if is_platform_admin():
        vaults = service.list_business_vaults_for_user(str(current_user.id))

    elif current_user.account_type == "individual":
        vaults = service.list_personal_vaults(str(current_user.id))

    elif current_user.account_type == "business":
        if PermissionService.has_org_permission(
            org_id=str(current_user.organization_id),
            user_id=str(current_user.id),
            permission="vault.write",
        ):
            vaults = service.list_business_vaults_for_admin(
                str(current_user.organization_id),
                str(current_user.id),   # ✅ REQUIRED
            )

        else:
            vaults = service.list_business_vaults_for_user(
                str(current_user.id)
            )
    else:
        vaults = []

    return render_template(
        "dashboard/vault_dashboard.html",
        vaults=vaults,
    )


# ==================================================
# CREATE VAULT
# ==================================================
@vault_bp.route("/create", methods=["POST"])
@login_required
def create_vault():
    service = vault_service()
    name = request.form.get("name", "").strip()

    if not name:
        flash("Vault name is required", "danger")
        return redirect(url_for("vault.dashboard"))

    try:
        if is_platform_admin():
            org_id = request.form.get("org_id")
            if not org_id:
                raise ValueError("Organization required")

            vault_id = service.create_business_vault(
                org_id=org_id,
                creator_user_id=str(current_user.id),
                name=name,
            )

        elif current_user.account_type == "business":
            vault_id = service.create_business_vault(
                org_id=str(current_user.organization_id),
                creator_user_id=str(current_user.id),
                name=name,
            )

        else:
            vault_id = service.create_personal_vault(
                user_id=str(current_user.id),
                name=name,
            )

        flash("Vault created", "success")
        return redirect(
            url_for("vault.view_vault", vault_id=vault_id)
        )

    except (PermissionError, ValueError) as e:
        flash(str(e), "danger")
        return redirect(url_for("vault.dashboard"))


# ==================================================
# VIEW VAULT
# ==================================================
@vault_bp.route("/<vault_id>")
@login_required
def view_vault(vault_id):
    service = vault_service()

    try:
        vault = current_app.db.vaults.find_one(
            {"_id": ObjectId(vault_id)}
        )
        if not vault:
            raise ValueError("Vault not found")

        # permission check
        service._get_user_permission(
            ObjectId(vault_id), ObjectId(current_user.id)
        )

        secrets = service.list_secrets(
            vault_id=vault_id,
            user_id=str(current_user.id),
        )

    except (PermissionError, ValueError) as e:
        flash(str(e), "danger")
        return redirect(url_for("vault.dashboard"))

    return render_template(
        "dashboard/vault_view.html",
        vault=vault,
        secrets=secrets,
    )


# ==================================================
# CREATE SECRET
# ==================================================
@vault_bp.route("/<vault_id>/secrets/new", methods=["GET", "POST"])
@login_required
def create_secret(vault_id):
    service = vault_service()

    vault = current_app.db.vaults.find_one(
        {"_id": ObjectId(vault_id)}
    )
    if not vault:
        flash("Vault not found", "danger")
        return redirect(url_for("vault.dashboard"))

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        value = request.form.get("value", "").strip()

        if not name or not value:
            flash("All fields required", "danger")
            return redirect(
                url_for("vault.create_secret", vault_id=vault_id)
            )

        try:
            service.add_secret(
                vault_id=vault_id,
                user_id=str(current_user.id),
                name=name,
                value=value,
            )
            flash("Secret added", "success")
            return redirect(
                url_for("vault.view_vault", vault_id=vault_id)
            )

        except PermissionError as e:
            flash(str(e), "danger")

    return render_template(
        "dashboard/secret_create.html",
        vault=vault,
    )


# ==================================================
# READ SECRET
# ==================================================
@vault_bp.route("/secret/<secret_id>")
@login_required
def read_secret(secret_id):
    service = vault_service()

    try:
        value = service.read_secret(
            secret_id=secret_id,
            user_id=str(current_user.id),
        )
    except (PermissionError, ValueError) as e:
        flash(str(e), "danger")
        return redirect(url_for("vault.dashboard"))

    return render_template(
        "dashboard/secret_view.html",
        value=value,
    )


# ==================================================
# COPY SECRET
# ==================================================
@vault_bp.route("/secret/<secret_id>/copy", methods=["POST"])
@login_required
def copy_secret(secret_id):
    service = vault_service()
    try:
        value = service.copy_secret(
            secret_id=secret_id,
            user_id=str(current_user.id),
        )
        return jsonify({"value": value})
    except Exception as e:
        return jsonify({"error": str(e)}), 403


# ==================================================
# DELETE / RESTORE SECRET
# ==================================================
@vault_bp.route("/secret/<secret_id>/delete", methods=["POST"])
@login_required
def soft_delete_secret(secret_id):
    service = vault_service()

    try:
        service.soft_delete_secret(
            secret_id=secret_id,
            user_id=str(current_user.id),
        )
        flash("Secret moved to trash", "warning")
    except Exception as e:
        flash(str(e), "danger")

    secret = current_app.db.vault_secrets.find_one(
        {"_id": ObjectId(secret_id)}
    )
    if secret:
        return redirect(
            url_for("vault.view_vault", vault_id=secret["vault_id"])
        )

    return redirect(url_for("vault.dashboard"))


@vault_bp.route("/secret/<secret_id>/restore", methods=["POST"])
@login_required
def restore_secret(secret_id):
    service = vault_service()

    try:
        service.restore_secret(
            secret_id=secret_id,
            user_id=str(current_user.id),
        )
        flash("Secret restored", "success")
    except Exception as e:
        flash(str(e), "danger")

    secret = current_app.db.vault_secrets.find_one(
        {"_id": ObjectId(secret_id)}
    )
    if secret:
        return redirect(
            url_for("vault.view_vault", vault_id=secret["vault_id"])
        )

    return redirect(url_for("vault.dashboard"))


# ==================================================
# VAULT TRASH
# ==================================================
@vault_bp.route("/<vault_id>/trash", endpoint="vault_trash")
@login_required
def vault_trash(vault_id):
    service = vault_service()

    vault = current_app.db.vaults.find_one(
        {"_id": ObjectId(vault_id)}
    )
    if not vault:
        flash("Vault not found", "danger")
        return redirect(url_for("vault.dashboard"))

    try:
        service._get_user_permission(
            ObjectId(vault_id), ObjectId(current_user.id)
        )

        secrets = list(
            current_app.db.vault_secrets.find(
                {
                    "vault_id": ObjectId(vault_id),
                    "deleted_at": {"$ne": None},
                },
                {"encrypted_value": 0},
            )
        )
    except PermissionError:
        flash("Access denied", "danger")
        return redirect(
            url_for("vault.view_vault", vault_id=vault_id)
        )

    return render_template(
        "dashboard/vault_trash.html",
        vault=vault,
        secrets=secrets,
    )


@vault_bp.route(
    "/business/<vault_id>/access",
    endpoint="manage_access",
)
@login_required
def manage_access(vault_id):
    vault = current_app.db.vaults.find_one(
        {"_id": ObjectId(vault_id)}
    )
    if not vault:
        flash("Vault not found", "danger")
        return redirect(url_for("vault.dashboard"))

    # Determine current user's org authority
    member = current_app.db.organization_members.find_one({
        "org_id": vault["org_id"],
        "user_id": ObjectId(current_user.id),
    })

    current_user_authority = member["authority"] if member else None

    # ❌ Users cannot open page
    if not (
        current_user_authority in ("owner", "admin")
        or current_user.role == ROLE_PLATFORM_SUPERADMIN
    ):
        flash("Access denied", "danger")
        return redirect(url_for("vault.dashboard"))

    members = OrganizationService().list_members(
        str(vault["org_id"])
    )

    permissions = {
        p["user_id"]: p
        for p in current_app.db.vault_permissions.find(
            {"vault_id": ObjectId(vault_id)}
        )
    }

    return render_template(
        "dashboard/vault_access.html",
        vault=vault,
        members=members,
        permissions=permissions,
        current_user_authority=current_user_authority,
    )

# ==================================================
# GRANT ACCESS
# ==================================================
@vault_bp.route(
    "/business/<vault_id>/access/grant",
    methods=["POST"],
    endpoint="grant_access",
)
@login_required
def grant_access(vault_id):
    service = vault_service()

    try:
        service.grant_access(
            vault_id=vault_id,
            user_id=request.form.get("user_id"),
            permission=request.form.get("permission"),
            granted_by=str(current_user.id),
        )
        flash("Access updated", "success")
    except Exception as e:
        flash(str(e), "danger")

    return redirect(
        url_for("vault.manage_access", vault_id=vault_id)
    )


# ==================================================
# REVOKE ACCESS
# ==================================================
@vault_bp.route(
    "/business/<vault_id>/access/revoke",
    methods=["POST"],
    endpoint="revoke_access",
)
@login_required
def revoke_access(vault_id):
    service = vault_service()

    try:
        service.revoke_access(
            vault_id=vault_id,
            user_id=request.form.get("user_id"),
            revoked_by=str(current_user.id),
        )
        flash("Access revoked", "warning")
    except Exception as e:
        flash(str(e), "danger")

    return redirect(
        url_for("vault.manage_access", vault_id=vault_id)
    )
