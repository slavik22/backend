from datetime import datetime
from decimal import Decimal
from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Text, Numeric
from sqlalchemy.orm import relationship

from extentions import db


def _dec(v):
    if v is None:
        return None
    if isinstance(v, Decimal):
        return float(v)
    return v

class Job(db.Model):
    __tablename__ = "jobs"
    id = Column(Integer, primary_key=True)
    company_id = Column(Integer, ForeignKey("companies.id"), nullable=False)
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    requirements = Column(Text)
    responsibilities = Column(Text)

    salary_min = Column(Numeric(10, 2))
    salary_max = Column(Numeric(10, 2))
    salary_token = Column(String(10), default="USDC")
    salary_usd_equivalent = Column(Numeric(10, 2))

    job_type = Column(String(50))  # full-time, part-time, contract, dao-contributor
    experience_level = Column(String(50))  # junior, mid, senior, lead
    location_type = Column(String(50))  # remote, hybrid, onsite
    location = Column(String(100))

    is_dao_job = Column(Boolean, default=False)
    uses_escrow = Column(Boolean, default=False)
    escrow_contract = Column(String(42))
    required_on_chain_proof = Column(Boolean, default=False)

    skills_required = Column(Text)  # JSON array
    benefits = Column(Text)

    is_active = Column(Boolean, default=True)
    views_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    applications = relationship("Application", backref="job", lazy="dynamic", cascade="all, delete-orphan")

    def to_dict(self, with_company=False):
        data = {
            "id": self.id,
            "company_id": self.company_id,
            "title": self.title,
            "description": self.description,
            "requirements": self.requirements,
            "responsibilities": self.responsibilities,
            "salary_min": _dec(self.salary_min),
            "salary_max": _dec(self.salary_max),
            "salary_token": self.salary_token,
            "salary_usd_equivalent": _dec(self.salary_usd_equivalent),
            "job_type": self.job_type,
            "experience_level": self.experience_level,
            "location_type": self.location_type,
            "location": self.location,
            "is_dao_job": self.is_dao_job,
            "uses_escrow": self.uses_escrow,
            "escrow_contract": self.escrow_contract,
            "required_on_chain_proof": self.required_on_chain_proof,
            "skills_required": self.skills_required,
            "benefits": self.benefits,
            "is_active": self.is_active,
            "views_count": self.views_count,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
        if with_company and self.company:
            data["company"] = self.company.to_dict()
        return data
