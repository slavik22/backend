from flask import Blueprint, jsonify
from sqlalchemy import func
from extentions import db
from models.job import Job
from models.user import User
from models.application import Application
from models.company import Company

stats_bp = Blueprint("stats", __name__)


# ============================================================
# JOBS - MONTHLY CREATION
# ============================================================
@stats_bp.get("/stats/jobs/monthly")
def jobs_monthly():
    """
    Monthly number of created jobs
    ---
    tags:
      - Stats
    responses:
      200:
        description: List of months with job creation count
        schema:
          type: array
          items:
            type: object
            properties:
              month: {type: string}
              count: {type: integer}
    """
    month_trunc = func.date_trunc("month", Job.created_at)

    rows = (
        db.session.query(
            month_trunc.label("month"),
            func.count(Job.id).label("count")
        )
        .filter(Job.created_at.isnot(None))
        .group_by(month_trunc)
        .order_by(month_trunc)
        .all()
    )

    return jsonify([
        {"month": row.month.strftime("%Y-%m") if row.month else None, "count": row.count}
        for row in rows
    ])


# ============================================================
# JOBS BY COMPANY
# ============================================================
@stats_bp.get("/stats/jobs/by-company")
def jobs_by_company():
    """
    Number of jobs grouped by company
    ---
    tags:
      - Stats
    responses:
      200:
        description: Job count per company
        schema:
          type: array
          items:
            type: object
            properties:
              company: {type: string}
              count: {type: integer}
    """
    rows = (
        db.session.query(
            Company.name,
            func.count(Job.id)
        )
        .join(Job, Job.company_id == Company.id)
        .group_by(Company.name)
        .order_by(func.count(Job.id).desc())
        .all()
    )

    return jsonify([{"company": row[0], "count": row[1]} for row in rows])


# ============================================================
# JOBS BY TYPE
# ============================================================
@stats_bp.get("/stats/jobs/by-type")
def jobs_by_type():
    """
    Number of jobs by job type
    ---
    tags:
      - Stats
    responses:
      200:
        description: Job count per job type
        schema:
          type: array
          items:
            type: object
            properties:
              type: {type: string}
              count: {type: integer}
    """
    rows = (
        db.session.query(
            Job.job_type,
            func.count(Job.id)
        )
        .group_by(Job.job_type)
        .order_by(func.count(Job.id).desc())
        .all()
    )

    return jsonify([{"type": row[0], "count": row[1]} for row in rows])


# ============================================================
# ACTIVE VS INACTIVE JOBS
# ============================================================
@stats_bp.get("/stats/jobs/active")
def jobs_active():
    """
    Number of active and inactive jobs
    ---
    tags:
      - Stats
    responses:
      200:
        description: Active/inactive job counts
        schema:
          type: object
          properties:
            active: {type: integer}
            inactive: {type: integer}
    """
    active = Job.query.filter_by(is_active=True).count()
    inactive = Job.query.filter_by(is_active=False).count()

    return jsonify({"active": active, "inactive": inactive})


# ============================================================
# APPLICATIONS PER DAY
# ============================================================
@stats_bp.get("/stats/applications/daily")
def applications_daily():
    """
    Daily applications statistics
    ---
    tags:
      - Stats
    responses:
      200:
        description: Number of applications per day
        schema:
          type: array
          items:
            type: object
            properties:
              day: {type: string}
              count: {type: integer}
    """
    day_trunc = func.date_trunc("day", Application.applied_at)

    rows = (
        db.session.query(
            day_trunc.label("day"),
            func.count(Application.id).label("count")
        )
        .filter(Application.applied_at.isnot(None))
        .group_by(day_trunc)
        .order_by(day_trunc)
        .all()
    )

    return jsonify([
        {"day": row.day.strftime("%Y-%m-%d") if row.day else None, "count": row.count}
        for row in rows
    ])


# ============================================================
# APPLICATIONS BY STATUS
# ============================================================
@stats_bp.get("/stats/applications/by-status")
def apps_by_status():
    """
    Number of applications grouped by status
    ---
    tags:
      - Stats
    responses:
      200:
        description: Application count per status
        schema:
          type: array
          items:
            type: object
            properties:
              status: {type: string}
              count: {type: integer}
    """
    rows = (
        db.session.query(
            Application.status,
            func.count(Application.id)
        )
        .group_by(Application.status)
        .order_by(func.count(Application.id).desc())
        .all()
    )

    return jsonify([{"status": row[0], "count": row[1]} for row in rows])


# ============================================================
# APPLICATIONS BY JOB
# ============================================================
@stats_bp.get("/stats/applications/by-job")
def apps_by_job():
    """
    Top jobs by number of applications (limit 10)
    ---
    tags:
      - Stats
    responses:
      200:
        description: Application count per job title
        schema:
          type: array
          items:
            type: object
            properties:
              job: {type: string}
              count: {type: integer}
    """
    rows = (
        db.session.query(
            Job.title,
            func.count(Application.id)
        )
        .join(Application, Application.job_id == Job.id)
        .group_by(Job.title)
        .order_by(func.count(Application.id).desc())
        .limit(10)
    )

    return jsonify([{"job": row[0], "count": row[1]} for row in rows])


# ============================================================
# APPLICATIONS BY COMPANY
# ============================================================
@stats_bp.get("/stats/applications/by-company")
def apps_by_company():
    """
    Applications grouped by company
    ---
    tags:
      - Stats
    responses:
      200:
        description: Application count per company
        schema:
          type: array
          items:
            type: object
            properties:
              company: {type: string}
              count: {type: integer}
    """
    rows = (
        db.session.query(
            Company.name,
            func.count(Application.id)
        )
        .join(Job, Job.company_id == Company.id)
        .join(Application, Application.job_id == Job.id)
        .group_by(Company.name)
        .order_by(func.count(Application.id).desc())
        .all()
    )

    return jsonify([{"company": row[0], "count": row[1]} for row in rows])


# ============================================================
# NEW USERS PER MONTH
# ============================================================
@stats_bp.get("/stats/users/monthly")
def users_monthly():
    """
    Monthly number of new users
    ---
    tags:
      - Stats
    responses:
      200:
        description: User count per month
        schema:
          type: array
          items:
            type: object
            properties:
              month: {type: string}
              count: {type: integer}
    """
    month_trunc = func.date_trunc("month", User.created_at)

    rows = (
        db.session.query(
            month_trunc.label("month"),
            func.count(User.id).label("count")
        )
        .filter(User.created_at.isnot(None))
        .group_by(month_trunc)
        .order_by(month_trunc)
        .all()
    )

    return jsonify([
        {"month": row.month.strftime("%Y-%m") if row.month else None, "count": row.count}
        for row in rows
    ])


# ============================================================
# USERS BY ROLES
# ============================================================
@stats_bp.get("/stats/users/roles")
def users_by_roles():
    """
    Number of users per role
    ---
    tags:
      - Stats
    responses:
      200:
        description: User count per role
        schema:
          type: array
          items:
            type: object
            properties:
              role: {type: string}
              count: {type: integer}
    """
    rows = (
        db.session.query(
            User.role,
            func.count(User.id)
        )
        .group_by(User.role)
        .all()
    )

    return jsonify([{"role": row[0], "count": row[1]} for row in rows])
