from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required

from extentions import db
from models.user import User
from models.company import Company
from models.job import Job
from models.application import Application
from helpers import current_user_jwt, admin_guard

admin_bp = Blueprint("admin", __name__)


@admin_bp.get("/admin/dashboard")
@jwt_required()
def admin_dashboard():
    """
    Admin dashboard
    ---
    tags:
      - Admin
    security:
      - Bearer: []
    """
    user = current_user_jwt()
    guard = admin_guard(user)
    if guard:
        return guard

    total_users = User.query.count()
    total_companies = Company.query.count()
    total_jobs = Job.query.count()
    total_applications = Application.query.count()
    recent_users = User.query.order_by(User.created_at.desc()).limit(5).all()
    pending_companies = Company.query.filter_by(is_verified=False).all()

    return jsonify(
        {
            "ok": True,
            "totals": {
                "users": total_users,
                "companies": total_companies,
                "jobs": total_jobs,
                "applications": total_applications,
            },
            "recent_users": [u.to_dict() for u in recent_users],
            "pending_companies": [c.to_dict() for c in pending_companies],
        }
    )


@admin_bp.post("/admin/verify-company/<int:company_id>")
@jwt_required()
def verify_company(company_id):
    """
    Verify company
    ---
    tags:
      - Admin
    security:
      - Bearer: []
    """
    user = current_user_jwt()
    guard = admin_guard(user)
    if guard:
        return guard

    company = Company.query.get_or_404(company_id)
    company.is_verified = True
    db.session.commit()
    return jsonify(
        {
            "ok": True,
            "message": f"Компанію {company.name} верифіковано!",
            "company": company.to_dict(),
        }
    )
