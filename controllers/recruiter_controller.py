from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required

from extentions import db
from models.company import Company
from models.job import Job
from models.application import Application
from models.user import User
from models.user_profile import UserProfile
from helpers import current_user_jwt, recruiter_guard

recruiter_bp = Blueprint("recruiter", __name__)


@recruiter_bp.get("/recruiter/dashboard")
@jwt_required()
def recruiter_dashboard():
    """
    Recruiter dashboard
    ---
    tags:
      - Recruiter
    security:
      - Bearer: []
    """
    user = current_user_jwt()
    guard = recruiter_guard(user)
    if guard:
        return guard

    company = user.company
    if not company:
        return jsonify(
            {
                "ok": True,
                "needs_company_profile": True,
                "message": "Створіть профіль компанії.",
            }
        )

    jobs = (
        Job.query.filter_by(company_id=company.id)
        .order_by(Job.created_at.desc())
        .all()
    )
    total_applications = (
        Application.query.join(Job)
        .filter(Job.company_id == company.id)
        .count()
    )
    pending_applications = (
        Application.query.join(Job)
        .filter(
            Job.company_id == company.id,
            Application.status == "pending",
        )
        .count()
    )

    return jsonify(
        {
            "ok": True,
            "company": company.to_dict(),
            "jobs": [j.to_dict() for j in jobs],
            "metrics": {
                "total_applications": total_applications,
                "pending_applications": pending_applications,
            },
        }
    )


@recruiter_bp.get("/recruiter/company")
@jwt_required()
def get_company():
    """
    Get recruiter company profile
    ---
    tags:
      - Recruiter
    security:
      - Bearer: []
    """
    user = current_user_jwt()
    guard = recruiter_guard(user)
    if guard:
        return guard

    if not user.company:
        return jsonify({"ok": True, "company": None})

    return jsonify({"ok": True, "company": user.company.to_dict()})


@recruiter_bp.post("/recruiter/company")
@jwt_required()
def create_company():
    """
    Create company profile
    ---
    tags:
      - Recruiter
    security:
      - Bearer: []
    """
    user = current_user_jwt()
    guard = recruiter_guard(user)
    if guard:
        return guard

    if user.company:
        # Вже є компанія — можна редіректити на edit
        return jsonify({"ok": True, "redirect": "/recruiter/company/edit"})

    data = request.get_json(force=True) or {}
    company = Company(
        recruiter_id=user.id,
        name=data.get("name"),
        website=data.get("website"),
        description=data.get("description"),
        logo_url=data.get("logo_url"),
        company_type=data.get("company_type"),
        treasury_address=data.get("treasury_address"),
        token_symbol=data.get("token_symbol"),
        founded_year=data.get("founded_year"),
        team_size=data.get("team_size"),
        location=data.get("location"),
    )
    db.session.add(company)
    db.session.commit()
    return (
        jsonify(
            {"ok": True, "message": "Компанію створено", "company": company.to_dict()}
        ),
        201,
    )


@recruiter_bp.put("/recruiter/company/edit")
@jwt_required()
def edit_company():
    """
    Edit company profile
    ---
    tags:
      - Recruiter
    security:
      - Bearer: []
    """
    user = current_user_jwt()
    guard = recruiter_guard(user)
    if guard:
        return guard

    company = user.company
    if not company:
        return (
            jsonify(
                {
                    "ok": False,
                    "error": "not_found",
                    "message": "Компанії немає.",
                }
            ),
            404,
        )

    data = request.get_json(force=True) or {}
    for field in [
        "name",
        "website",
        "description",
        "logo_url",
        "company_type",
        "treasury_address",
        "token_symbol",
        "team_size",
        "location",
    ]:
        if field in data:
            setattr(company, field, data[field])

    if "founded_year" in data:
        company.founded_year = data["founded_year"]

    db.session.commit()
    return jsonify(
        {"ok": True, "message": "Компанію оновлено", "company": company.to_dict()}
    )


@recruiter_bp.get("/recruiter/job/<int:job_id>/applications")
@jwt_required()
def job_applications(job_id):
    """
    Get applications for a job
    ---
    tags:
      - Recruiter
    security:
      - Bearer: []
    """
    user = current_user_jwt()
    guard = recruiter_guard(user)
    if guard:
        return guard

    job = Job.query.get_or_404(job_id)
    if job.company.recruiter_id != user.id and user.role != "admin":
        return jsonify({"ok": False, "error": "forbidden"}), 403

    apps = (
        Application.query.filter_by(job_id=job_id)
        .order_by(Application.applied_at.desc())
        .all()
    )
    return jsonify(
        {
            "ok": True,
            "job": job.to_dict(),
            "applications": [a.to_dict() for a in apps],
        }
    )


@recruiter_bp.put("/recruiter/application/<int:app_id>/update")
@jwt_required()
def update_application(app_id):
    """
    Update application status/notes
    ---
    tags:
      - Recruiter
    security:
      - Bearer: []
    """
    user = current_user_jwt()
    guard = recruiter_guard(user)
    if guard:
        return guard

    application = Application.query.get_or_404(app_id)
    if application.job.company.recruiter_id != user.id and user.role != "admin":
        return jsonify({"ok": False, "error": "forbidden"}), 403

    data = request.get_json(force=True) or {}
    if "status" in data:
        application.status = data["status"]
    if "recruiter_notes" in data:
        application.recruiter_notes = data["recruiter_notes"]

    db.session.commit()
    return jsonify(
        {
            "ok": True,
            "message": "Статус оновлено",
            "application": application.to_dict(),
        }
    )


@recruiter_bp.get("/recruiter/candidate/<int:user_id>")
@jwt_required()
def recruiter_candidate(user_id):
    """
    Get candidate profile (for recruiter)
    ---
    tags:
      - Recruiter
    security:
      - Bearer: []
    """
    user = current_user_jwt()
    guard = recruiter_guard(user)
    if guard:
        return guard

    # доступ тільки якщо кандидат подавався на вакансії цього рекрутера
    applied = (
        db.session.query(Application)
        .join(Job, Application.job_id == Job.id)
        .join(Company, Job.company_id == Company.id)
        .filter(Application.user_id == user_id, Company.recruiter_id == user.id)
        .first()
    )
    if not applied and user.role != "admin":
        return jsonify({"ok": False, "error": "forbidden"}), 403

    candidate = User.query.get_or_404(user_id)
    profile = getattr(candidate, "profile", None)

    data = {
        "id": candidate.id,
        "full_name": getattr(profile, "full_name", None),
        "email": candidate.email,
        "phone": getattr(profile, "phone", None),
        "location": getattr(profile, "location", None),
        "github": getattr(profile, "github", None),
        "linkedin": getattr(profile, "linkedin", None),
        # API повертає "portfolio", а в моделі, скоріш за все, поле portfolio_url
        "portfolio": getattr(profile, "portfolio_url", None),
        # React очікує рядок (потім .split(',')), тому лишаємо текст
        "skills": getattr(profile, "skills", None) or "",
        "bio": getattr(profile, "bio", None),
    }
    return jsonify({"ok": True, "candidate": data})
