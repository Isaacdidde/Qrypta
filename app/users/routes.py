from flask import render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user

from app.extensions import bcrypt
from . import users_bp
from .services import UserService


@users_bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    service = UserService(bcrypt)
    profile = service.get_profile(current_user.id)

    if request.method == "POST":
        full_name = request.form.get("full_name")
        phone = request.form.get("phone")
        mfa_question = request.form.get("mfa_question")
        mfa_answer = request.form.get("mfa_answer")

        service.create_or_update_profile(
            user_id=current_user.id,
            full_name=full_name,
            phone=phone,
            mfa_question=mfa_question,
            mfa_answer=mfa_answer,
        )

        flash("Profile updated successfully", "success")
        return redirect(url_for("users.profile"))

    return render_template(
        "dashboard/user_profile.html",
        profile=profile,
    )
