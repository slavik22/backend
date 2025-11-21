from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required

from extentions import db
from models.job import Job
from models.company import Company
from models.application import Application
from helpers import current_user_jwt, recruiter_guard, to_decimal

jobs_bp = Blueprint("jobs", __name__)


@jobs_bp.get("/jobs")
def jobs_list():
    """
    Get list of active jobs (with filters)
    ---
    tags:
      - Jobs
    """
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)
    job_type = request.args.get("type")
    token = request.args.get("token")
    is_dao = request.args.get("dao")
    blockchain = request.args.get("blockchain")

    query = Job.query.filter_by(is_active=True)
    if job_type:
        query = query.filter_by(job_type=job_type)
    if token:
        query = query.filter_by(salary_token=token)
    if is_dao:
        query = query.filter_by(is_dao_job=True)
    if blockchain:
        query = query.filter_by(blockchain=blockchain)

    pagination = query.order_by(Job.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    return jsonify(
        {
            "ok": True,
            "page": pagination.page,
            "pages": pagination.pages,
            "total": pagination.total,
            "items": [j.to_dict(with_company=True) for j in pagination.items],
        }
    )


@jobs_bp.get("/job/<int:job_id>")
@jwt_required(optional=True)
def job_detail(job_id):
    """
    Get job details
    ---
    tags:
      - Jobs
    """
    job = Job.query.get_or_404(job_id)
    job.views_count += 1
    db.session.commit()

    has_applied = False
    user = current_user_jwt()
    if user:
        has_applied = (
            Application.query.filter_by(job_id=job_id, user_id=user.id).first()
            is not None
        )

    return jsonify(
        {"ok": True, "job": job.to_dict(with_company=True), "has_applied": has_applied}
    )


@jobs_bp.post("/job/<int:job_id>/apply")
@jwt_required()
def apply_job(job_id):
    """
    Apply to a job
    ---
    tags:
      - Jobs
    """
    user = current_user_jwt()
    if not user:
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    if user.role != "user":
        return jsonify(
            {
                "ok": False,
                "error": "forbidden",
                "message": "Тільки кандидати можуть подавати заявки.",
            }
        ), 403

    job = Job.query.get_or_404(job_id)
    existing = Application.query.filter_by(job_id=job_id, user_id=user.id).first()
    if existing:
        return jsonify(
            {
                "ok": False,
                "error": "duplicate",
                "message": "Ви вже подали заявку на цю вакансію.",
            }
        ), 409

    data = request.get_json(force=True) or {}
    application = Application(
        job_id=job.id,
        user_id=user.id,
        cover_letter=data.get("cover_letter"),
        resume_url=data.get("resume_url"),
    )
    db.session.add(application)
    db.session.commit()
    return (
        jsonify(
            {
                "ok": True,
                "message": "Заявку відправлено",
                "application": application.to_dict(),
            }
        ),
        201,
    )


@jobs_bp.post("/recruiter/job/create")
@jwt_required()
def create_job():
    """
    Create job
    ---
    tags:
      - Recruiter
    """
    user = current_user_jwt()
    guard = recruiter_guard(user)
    if guard:
        return guard

    company = user.company
    if not company:
        return jsonify(
            {
                "ok": False,
                "error": "no_company",
                "message": "Спочатку створіть профіль компанії.",
            }
        ), 400

    data = request.get_json(force=True) or {}
    job = Job(
        company_id=company.id,
        title=data.get("title"),
        description=data.get("description"),
        requirements=data.get("requirements"),
        responsibilities=data.get("responsibilities"),
        salary_min=to_decimal(data.get("salary_min")),
        salary_max=to_decimal(data.get("salary_max")),
        salary_token=data.get("salary_token", "USDC"),
        salary_usd_equivalent=to_decimal(data.get("salary_usd_equivalent")),
        job_type=data.get("job_type"),
        experience_level=data.get("experience_level"),
        location_type=data.get("location_type"),
        location=data.get("location"),
        is_dao_job=bool(data.get("is_dao_job")),
        uses_escrow=bool(data.get("uses_escrow")),
        escrow_contract=data.get("escrow_contract"),
        required_on_chain_proof=bool(data.get("required_on_chain_proof")),
        skills_required=data.get("skills_required"),
        benefits=data.get("benefits"),
        # blockchain=data.get("blockchain"),
    )
    db.session.add(job)
    db.session.commit()
    return jsonify({"ok": True, "message": "Вакансію створено", "job": job.to_dict()}), 201


@jobs_bp.put("/recruiter/job/<int:job_id>/edit")
@jwt_required()
def edit_job(job_id):
    """
    Edit job
    ---
    tags:
      - Recruiter
    """
    user = current_user_jwt()
    guard = recruiter_guard(user)
    if guard:
        return guard

    job = Job.query.get_or_404(job_id)
    if job.company.recruiter_id != user.id and user.role != "admin":
        return jsonify({"ok": False, "error": "forbidden"}), 403

    data = request.get_json(force=True) or {}
    for field in [
        "title",
        "description",
        # "blockchain",
        "requirements",
        "responsibilities",
        "salary_token",
        "job_type",
        "experience_level",
        "location_type",
        "location",
        "escrow_contract",
        "skills_required",
        "benefits",
    ]:
        if field in data:
            setattr(job, field, data[field])

    for numeric in ["salary_min", "salary_max", "salary_usd_equivalent"]:
        if numeric in data:
            setattr(job, numeric, to_decimal(data[numeric]))

    for boolean in ["is_dao_job", "uses_escrow", "required_on_chain_proof", "is_active"]:
        if boolean in data:
            setattr(job, boolean, bool(data[boolean]))

    db.session.commit()
    return jsonify({"ok": True, "message": "Вакансію оновлено", "job": job.to_dict()})
