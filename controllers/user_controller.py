from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required

from extentions import db
from models.application import Application
from models.user_profile import UserProfile
from helpers import current_user_jwt

user_bp = Blueprint("user", __name__)


@user_bp.get("/dashboard")
@jwt_required()
def dashboard():
    """
    Get user dashboard
    ---
    tags:
      - User
    """
    user = current_user_jwt()
    if not user:
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    if user.role == "recruiter":
        return jsonify({"ok": True, "redirect": "/recruiter/dashboard"})
    if user.role == "admin":
        return jsonify({"ok": True, "redirect": "/admin/dashboard"})

    apps = (
        Application.query.filter_by(user_id=user.id)
        .order_by(Application.applied_at.desc())
        .all()
    )

    return jsonify(
        {
            "ok": True,
            "applications": [
                {
                    **a.to_dict(),
                    "job_title": a.job.title if a.job else None,
                    "company_name": a.job.company.name
                    if a.job and a.job.company
                    else None,
                }
                for a in apps
            ],
        }
    )


@user_bp.get("/profile")
@jwt_required()
def get_profile():
    """
    Get user profile
    ---
    tags:
      - User
    """
    user = current_user_jwt()
    if not user:
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    base = user.profile.to_dict() if user.profile else {}
    base["email"] = user.email
    base["role"] = user.role

    return jsonify({"ok": True, "profile": base})


@user_bp.put("/profile")
@jwt_required()
def update_profile():
    """
    Update user profile
    ---
    tags:
      - User
    """
    user = current_user_jwt()
    if not user:
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    data = request.get_json(force=True) or {}

    # User.email / User.role
    if "email" in data and data["email"]:
        new_email = (data["email"] or "").strip() or None
        from models.user import User

        if (
            new_email
            and User.query.filter(User.email == new_email, User.id != user.id).first()
        ):
            return (
                jsonify(
                    {
                        "ok": False,
                        "error": "email_exists",
                        "message": "Email вже зайнятий",
                    }
                ),
                409,
            )
        user.email = new_email

    if "role" in data and data["role"] in ["user", "recruiter"]:
        user.role = data["role"]

    profile = user.profile or UserProfile(user_id=user.id)
    for field in [
        "full_name",
        "phone",
        # "blockchain",
        "telegram",
        "discord",
        "github",
        "linkedin",
        "portfolio_url",
        "ens_domain",
        "skills",
        "bio",
        "preferred_tokens",
        "nft_portfolio",
    ]:
        if field in data:
            setattr(profile, field, data[field])

    if "experience_years" in data:
        profile.experience_years = (
            int(data["experience_years"])
            if data["experience_years"] is not None
            else None
        )

    db.session.add(user)
    db.session.add(profile)
    db.session.commit()

    merged = profile.to_dict()
    merged["email"] = user.email
    merged["role"] = user.role

    return jsonify({"ok": True, "message": "Профіль оновлено", "profile": merged})
