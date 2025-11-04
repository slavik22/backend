from datetime import datetime

from flask_login import UserMixin
from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.orm import relationship

from extentions import db


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(120), unique=True, nullable=False)
    password_hash = Column(String(255))
    role = Column(String(20), default="user")  # user, recruiter, admin
    wallet_address = Column(String(42), unique=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    profile = relationship("UserProfile", backref="user", uselist=False, cascade="all, delete-orphan")
    applications = relationship("Application", backref="user", lazy="dynamic", cascade="all, delete-orphan")
    company = relationship("Company", backref="recruiter", uselist=False, cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "email": self.email,
            "role": self.role,
            "wallet_address": self.wallet_address,
            "created_at": self.created_at.isoformat(),
            "profile": self.profile.to_dict() if self.profile else None,
        }