from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required

from extentions import db
from models.job import Job
from models.company import Company
from models.application import Application
from helpers import current_user_jwt, recruiter_guard, to_decimal

jobs_bp = Blueprint("jobs", __name__)


# ============================================================
# GET JOB LIST
# ============================================================
@jobs_bp.get("/jobs")
def jobs_list():
    """
    Get list of active jobs (with filters)
    ---
    tags:
      - Jobs
    parameters:
      - name: page
        in: query
        type: integer
        required: false
      - name: per_page
        in: query
        type: integer
        required: false
      - name: type
        in: query
        type: string
        description: Job type (full-time, part-time)
      - name: token
        in: query
        type: string
        description: Salary token (USDC, DAI, ETH)
      - name: dao
        in: query
        type: boolean
        description: Only DAO jobs
      - name: blockchain
        in: query
        type: string
        description: Blockchain (Ethereum, Polygon, Solana)
    responses:
      200:
        description: List of jobs
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


# ============================================================
# JOB DETAIL
# ============================================================
@jobs_bp.get("/job/<int:job_id>")
@jwt_required(optional=True)
def job_detail(job_id):
    """
    Get job details
    ---
    tags:
      - Jobs
    parameters:
      - name: job_id
        in: path
        type: integer
        required: true
    responses:
      200:
        description: Job details
      404:
        description: Job not found
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


# ============================================================
# APPLY TO JOB
# ============================================================
@jobs_bp.post("/job/<int:job_id>/apply")
@jwt_required()
def apply_job(job_id):
    """
    Apply to a job (candidate only)
    ---
    tags:
      - Jobs
    security:
      - Bearer: []
    parameters:
      - name: job_id
        in: path
        type: integer
        required: true
      - name: body
        in: body
        required: false
        schema:
          type: object
          properties:
            cover_letter:
              type: string
            resume_url:
              type: string
    responses:
      201:
        description: Application submitted
      403:
        description: Only candidates can apply
      409:
        description: Already applied
    """
    user = current_user_jwt()
    if not user:
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    if user.role != "user":
        return jsonify(
            {"ok": False, "error": "forbidden", "message": "Only candidates can apply."}
        ), 403

    job = Job.query.get_or_404(job_id)

    existing = Application.query.filter_by(job_id=job_id, user_id=user.id).first()
    if existing:
        return jsonify(
            {"ok": False, "error": "duplicate", "message": "Already applied."}
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
            {"ok": True, "message": "Application sent", "application": application.to_dict()}
        ),
        201,
    )


# ============================================================
# CREATE JOB (RECRUITER)
# ============================================================
@jobs_bp.post("/recruiter/job/create")
@jwt_required()
def create_job():
    """
    Create a new job (recruiter)
    ---
    tags:
      - Recruiter
    security:
      - Bearer: []
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            title: {type: string}
            description: {type: string}
            requirements: {type: string}
            responsibilities: {type: string}
            salary_min: {type: number}
            salary_max: {type: number}
            salary_token: {type: string}
            salary_usd_equivalent: {type: number}
            job_type: {type: string}
            experience_level: {type: string}
            location_type: {type: string}
            location: {type: string}
            is_dao_job: {type: boolean}
            uses_escrow: {type: boolean}
            escrow_contract: {type: string}
            required_on_chain_proof: {type: boolean}
            skills_required: {type: string}
            benefits: {type: string}
    responses:
      201:
        description: Job created
      400:
        description: Recruiter has no company profile
      403:
        description: Forbidden (not recruiter)
    """
    user = current_user_jwt()
    guard = recruiter_guard(user)
    if guard:
        return guard

    company = user.company
    if not company:
        return jsonify(
            {"ok": False, "error": "no_company", "message": "Create company profile first."}
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
    )
    db.session.add(job)
    db.session.commit()

    return jsonify({"ok": True, "message": "Job created", "job": job.to_dict()}), 201


# ============================================================
# EDIT JOB
# ============================================================
@jobs_bp.put("/recruiter/job/<int:job_id>/edit")
@jwt_required()
def edit_job(job_id):
    """
    Edit a job (recruiter)
    ---
    tags:
      - Recruiter
    security:
      - Bearer: []
    parameters:
      - name: job_id
        in: path
        type: integer
        required: true
      - name: body
        in: body
        schema:
          type: object
          description: Fields to update
    responses:
      200:
        description: Job updated
      403:
        description: Forbidden
      404:
        description: Job not found
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
        "title", "description", "requirements", "responsibilities",
        "salary_token", "job_type", "experience_level", "location_type",
        "location", "escrow_contract", "skills_required", "benefits",
    ]:
        if field in data:
            setattr(job, field, data[field])

    for n in ["salary_min", "salary_max", "salary_usd_equivalent"]:
        if n in data:
            setattr(job, n, to_decimal(data[n]))

    for boolean in ["is_dao_job", "uses_escrow", "required_on_chain_proof", "is_active"]:
        if boolean in data:
            setattr(job, boolean, bool(data[boolean]))

    db.session.commit()
    return jsonify({"ok": True, "message": "Job updated", "job": job.to_dict()})
