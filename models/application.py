from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship

from extentions import db


class Application(db.Model):
    __tablename__ = "applications"
    id = Column(Integer, primary_key=True)
    job_id = Column(Integer, ForeignKey("jobs.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    cover_letter = Column(Text)
    resume_url = Column(String(200))
    status = Column(String(20), default="pending")  # pending, reviewed, interview, accepted, rejected
    recruiter_notes = Column(Text)
    applied_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "job_id": self.job_id,
            "user_id": self.user_id,  # <-- додали
            "user": {
                "id": self.user.id,
                "name": self.user.profile.full_name,
                "email": self.user.email,
            } if self.user else None,
            "resume_url": self.resume_url,
            "cover_letter": self.cover_letter,
            "status": self.status,
            "recruiter_notes": self.recruiter_notes,
            "applied_at": self.applied_at.isoformat() if self.applied_at else None,
        }