# app/__init__.py

from flask import Flask, current_app
from flask_login import current_user
from bson import ObjectId

from app.config import DevelopmentConfig, ProductionConfig
from app.extensions import bcrypt, login_manager, init_mongo
from app.core.permissions import PermissionService
from app.users.models import ROLE_PLATFORM_SUPERADMIN

# -------------------------------
# Timezone (UTC → IST)
# -------------------------------
from datetime import datetime
import pytz

UTC = pytz.utc
IST = pytz.timezone("Asia/Kolkata")


def utc_to_ist(dt: datetime | None):
    """
    Convert UTC datetime to IST for display purposes.
    Storage must always remain UTC.
    """
    if dt is None:
        return None

    if dt.tzinfo is None:
        dt = UTC.localize(dt)

    return dt.astimezone(IST)


# -------------------------------------------------
# Application Factory
# -------------------------------------------------
def create_app():
    app = Flask(__name__)

    # -------------------------------------------------
    # Configuration
    # -------------------------------------------------
    env = app.config.get("FLASK_ENV", "development")

    if env == "production":
        app.config.from_object(ProductionConfig)
    else:
        app.config.from_object(DevelopmentConfig)

    # -------------------------------------------------
    # Initialize Extensions
    # -------------------------------------------------
    bcrypt.init_app(app)
    login_manager.init_app(app)

    login_manager.login_view = "auth.login"
    login_manager.session_protection = "strong"

    # -------------------------------------------------
    # Database
    # -------------------------------------------------
    init_mongo(app)  # sets app.db

    # -------------------------------------------------
    # Global Jinja Filters
    # -------------------------------------------------
    app.jinja_env.filters["ist"] = utc_to_ist

    # -------------------------------------------------
    # 🚫 Invitation-only onboarding
    # -------------------------------------------------
    @app.before_request
    def invitation_only_onboarding():
        """
        Business users are NOT forced to create organizations.
        They can exist without an org and must join via invitation.
        """
        return None

    # -------------------------------------------------
    # Global Context Processor
    # Inject organization role flags into templates
    # -------------------------------------------------
    @app.context_processor
    def inject_org_roles():
        if not current_user.is_authenticated:
            return {}

        # Platform superadmin → global access
        if current_user.role == ROLE_PLATFORM_SUPERADMIN:
            return {
                "is_owner": False,
                "is_admin": False,
                "is_manager": False,
            }

        # Business user without organization
        if (
            current_user.account_type != "business"
            or not current_user.organization_id
        ):
            return {
                "is_owner": False,
                "is_admin": False,
                "is_manager": False,
            }

        org_id = str(current_user.organization_id)
        user_id = str(current_user.id)

        return {
            "is_owner": PermissionService.is_owner(org_id, user_id),
            "is_admin": PermissionService.is_admin(org_id, user_id),
            "is_manager": PermissionService.is_manager(org_id, user_id),
        }

    # -------------------------------------------------
    # Blueprints
    # -------------------------------------------------
    from app.public.routes import public_bp
    from app.auth import auth_bp
    from app.users import users_bp
    from app.organizations import organizations_bp
    from app.vault import vault_bp
    from app.admin import admin_bp
    from app.audit import audit_bp

    app.register_blueprint(public_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(organizations_bp)
    app.register_blueprint(vault_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(audit_bp)

    return app


# -------------------------------------------------
# Flask-Login User Loader
# -------------------------------------------------
@login_manager.user_loader
def load_user(user_id: str):
    """
    Given a user ID stored in the session, return a LoginUser object.
    """
    db = current_app.db

    user = db.users.find_one({"_id": ObjectId(user_id)})
    if not user:
        return None

    from app.auth.routes import LoginUser
    return LoginUser(user)
