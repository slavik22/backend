from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required

from extentions import db
from models.application import Application
from models.user_profile import UserProfile
from helpers import current_user_jwt

user_bp = Blueprint("user", __name__)


# ============================================================
# USER DASHBOARD
# ============================================================
@user_bp.get("/dashboard")
@jwt_required()
def dashboard():
    """
    Get user dashboard information
    ---
    tags:
      - User
    security:
      - Bearer: []
    responses:
      200:
        description: User dashboard data
      401:
        description: Unauthorized
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


# ============================================================
# GET PROFILE
# ============================================================
@user_bp.get("/profile")
@jwt_required()
def get_profile():
    """
    Get user profile data
    ---
    tags:
      - User
    security:
      - Bearer: []
    responses:
      200:
        description: Profile returned
      401:
        description: Unauthorized
    """
    user = current_user_jwt()
    if not user:
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    base = user.profile.to_dict() if user.profile else {}
    base["email"] = user.email
    base["role"] = user.role

    return jsonify({"ok": True, "profile": base})


# ============================================================
# UPDATE PROFILE
# ============================================================
@user_bp.put("/profile")
@jwt_required()
def update_profile():
    """
    Update user profile information
    ---
    tags:
      - User
    security:
      - Bearer: []
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          description: User profile fields to update
          properties:
            email: {type: string}
            role:
              type: string
              enum: ["user", "recruiter"]
            full_name: {type: string}
            phone: {type: string}
            telegram: {type: string}
            discord: {type: string}
            github: {type: string}
            linkedin: {type: string}
            portfolio_url: {type: string}
            ens_domain: {type: string}
            skills: {type: string}
            bio: {type: string}
            preferred_tokens: {type: string}
            nft_portfolio: {type: string}
            experience_years: {type: integer}
    responses:
      200:
        description: Profile updated
      401:
        description: Unauthorized
      409:
        description: Email already exists
    """
    user = current_user_jwt()
    if not user:
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    data = request.get_json(force=True) or {}

    # ---------------------------
    # Update user email and role
    # ---------------------------
    if "email" in data and data["email"]:
        new_email = (data["email"] or "").strip() or None
        from models.user import User

        if new_email and User.query.filter(User.email == new_email, User.id != user.id).first():
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

    # ---------------------------
    # Update user profile fields
    # ---------------------------
    profile = user.profile or UserProfile(user_id=user.id)

    for field in [
        "full_name",
        "phone",
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
