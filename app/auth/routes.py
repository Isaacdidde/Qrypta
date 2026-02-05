# app/auth/routes.py

from flask import (
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
)
from flask_login import (
    login_user,
    logout_user,
    UserMixin,
    current_user,
)

from app.extensions import bcrypt
from app.core.audit import AuditLogger
from app.organizations.invitations.services import InvitationService
from . import auth_bp
from .services import AuthService


# ==================================================
# Flask-Login User Adapter
# ==================================================
class LoginUser(UserMixin):
    def __init__(self, user_dict: dict):
        self.id = str(user_dict["_id"])
        self.email = user_dict["email"]
        self.role = user_dict.get("role")
        self.account_type = user_dict.get("account_type", "individual")
        self.organization_id = user_dict.get("organization_id")


# ==================================================
# Registration (OTP REQUIRED)
# ==================================================
@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    next_page = request.args.get("next")

    if current_user.is_authenticated:
        return redirect(next_page or _post_login_redirect(current_user))

    if request.method == "POST":
        account_type = request.form.get("account_type", "individual")

        # -----------------------------
        # Input validation
        # -----------------------------
        if account_type == "business":
            email = request.form.get("business_email")
            company_name = request.form.get("company_name")
            if not email or not company_name:
                flash("Business email and company name are required", "danger")
                return redirect(request.url)
        else:
            email = request.form.get("email")
            full_name = request.form.get("full_name")
            if not email or not full_name:
                flash("Full name and email are required", "danger")
                return redirect(request.url)

        password = request.form.get("password")
        if not password:
            flash("Password is required", "danger")
            return redirect(request.url)

        try:
            # Create user (NO login yet)
            AuthService(bcrypt).register_user(
                account_type=account_type,
                email=email,
                password=password,
                full_name=request.form.get("full_name"),
                mobile=request.form.get("mobile"),
                company_name=request.form.get("company_name"),
                company_size=request.form.get("company_size"),
                address=request.form.get("address"),
                city=request.form.get("city"),
                country=request.form.get("country"),
                pincode=request.form.get("pincode"),
            )

            # 🔐 Start OTP flow immediately
            AuthService(bcrypt).initiate_login_otp(
                email=email,
                password=password,
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent"),
            )

            session["otp_email"] = email
            session["next_page"] = next_page

            flash("OTP sent to your email. Please verify.", "info")
            return redirect(url_for("auth.verify_login_otp"))

        except ValueError as exc:
            flash(str(exc), "danger")

    return render_template("auth/register.html", next=next_page)


# ==================================================
# Login – STEP 1 (Password → OTP)
# ==================================================
@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    next_page = request.args.get("next")

    if current_user.is_authenticated:
        return redirect(next_page or _post_login_redirect(current_user))

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        if not email or not password:
            flash("Email and password are required", "danger")
            return redirect(request.url)

        try:
            AuthService(bcrypt).initiate_login_otp(
                email=email,
                password=password,
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent"),
            )

            session["otp_email"] = email
            session["next_page"] = next_page

            return redirect(url_for("auth.verify_login_otp"))

        except ValueError as exc:
            AuditLogger().log_event(
                user_id=None,
                action="auth.login.password_failed",
                resource_type="user",
                resource_id=email,
                metadata={"email": email, "ip": request.remote_addr},
            )
            flash(str(exc), "danger")

    return render_template("auth/login.html", next=next_page)


# ==================================================
# Login – STEP 2 (Verify OTP)
# ==================================================
@auth_bp.route("/login/verify-otp", methods=["GET", "POST"])
def verify_login_otp():
    email = session.get("otp_email")
    if not email:
        flash("Session expired. Please log in again.", "warning")
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        otp = request.form.get("otp")
        if not otp:
            flash("OTP is required", "danger")
            return redirect(request.url)

        try:
            user_data = AuthService(bcrypt).verify_login_otp(
                email=email,
                otp=otp,
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent"),
            )

            session.pop("otp_email", None)
            next_page = session.pop("next_page", None)

            user = LoginUser(user_data)
            login_user(user)

            _finalize_invite_if_present(user.id)

            AuditLogger().log_event(
                user_id=user.id,
                action="auth.login.success",
                resource_type="user",
                resource_id=user.id,
            )

            return redirect(next_page or _post_login_redirect(user))

        except ValueError as exc:
            AuditLogger().log_event(
                user_id=None,
                action="auth.login.otp_failed",
                resource_type="user",
                resource_id=email,
            )
            flash(str(exc), "danger")

    return render_template("auth/verify_otp.html")


# ==================================================
# Forgot Password
# ==================================================
@auth_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        AuthService(bcrypt).initiate_password_reset(
            email=request.form.get("email"),
            ip_address=request.remote_addr,
        )
        flash("If the email exists, a reset code has been sent.", "info")
        return redirect(url_for("auth.reset_password"))

    return render_template("auth/forgot_password.html")


# ==================================================
# Reset Password
# ==================================================
@auth_bp.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":
        try:
            AuthService(bcrypt).reset_password_with_otp(
                email=request.form.get("email"),
                otp=request.form.get("otp"),
                new_password=request.form.get("password"),
                ip_address=request.remote_addr,
            )
            flash("Password reset successful. Please log in.", "success")
            return redirect(url_for("auth.login"))

        except ValueError as exc:
            flash(str(exc), "danger")

    return render_template("auth/reset_password.html")


# ==================================================
# Logout
# ==================================================
@auth_bp.route("/logout")
def logout():
    if current_user.is_authenticated:
        AuditLogger().log_event(
            user_id=str(current_user.id),
            action="auth.logout",
            resource_type="user",
            resource_id=str(current_user.id),
        )

    logout_user()
    flash("Logged out successfully.", "info")
    return redirect(url_for("auth.login"))


# ==================================================
# Invitation Finalizer
# ==================================================
def _finalize_invite_if_present(user_id: str):
    token = session.pop("pending_invite_token", None)
    if token:
        try:
            InvitationService().accept(token=token, user_id=user_id)
        except Exception:
            pass


# ==================================================
# Post-login Redirect (🔥 IMPORTANT FIX)
# ==================================================
def _post_login_redirect(user: LoginUser):
    # Platform admin
    if user.role == "platform_superadmin":
        return url_for("admin.dashboard")

    # ✅ Business owner FIRST LOGIN (no org yet)
    if user.account_type == "business" and not user.organization_id:
        return url_for("organizations.setup")

    # Business user with org
    if user.account_type == "business":
        return url_for("organizations.dashboard")

    # Individual user
    return url_for("vault.dashboard")
