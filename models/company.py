from datetime import datetime
from sqlalchemy.orm import relationship
from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Text

from extentions import db


class Company(db.Model):
    __tablename__ = "companies"
    id = Column(Integer, primary_key=True)
    recruiter_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    name = Column(String(100), nullable=False)
    website = Column(String(200))
    description = Column(Text)
    logo_url = Column(String(200))
    company_type = Column(String(50))  # startup, dao, protocol, exchange...
    treasury_address = Column(String(42))
    token_symbol = Column(String(10))
    founded_year = Column(Integer)
    team_size = Column(String(20))
    location = Column(String(100))
    is_verified = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    jobs = relationship("Job", backref="company", lazy="dynamic", cascade="all, delete-orphan")

    def to_dict(self, include_jobs=False):
        data = {
            "id": self.id,
            "recruiter_id": self.recruiter_id,
            "name": self.name,
            "website": self.website,
            "description": self.description,
            "logo_url": self.logo_url,
            "company_type": self.company_type,
            "treasury_address": self.treasury_address,
            "token_symbol": self.token_symbol,
            "founded_year": self.founded_year,
            "team_size": self.team_size,
            "location": self.location,
            "is_verified": self.is_verified,
            "created_at": self.created_at.isoformat(),
        }
        if include_jobs:
            data["jobs"] = [j.to_dict() for j in self.jobs.all()]
        return data
