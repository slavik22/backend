from datetime import datetime

from sqlalchemy import Column, Integer, ForeignKey, String, Text
from sqlalchemy.sql.sqltypes import DateTime

from extentions import db


class UserProfile(db.Model):
    __tablename__ = "user_profiles"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    full_name = Column(String(100))
    phone = Column(String(20))
    telegram = Column(String(50))
    discord = Column(String(50))
    github = Column(String(100))
    linkedin = Column(String(100))
    portfolio_url = Column(String(200))
    ens_domain = Column(String(100))
    skills = Column(Text)  # JSON string
    experience_years = Column(Integer)
    bio = Column(Text)
    preferred_tokens = Column(String(200))  # ETH, USDC, DAI...
    nft_portfolio = Column(Text)  # JSON array
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "full_name": self.full_name,
            "phone": self.phone,
            "telegram": self.telegram,
            "discord": self.discord,
            "github": self.github,
            "linkedin": self.linkedin,
            "portfolio_url": self.portfolio_url,
            "ens_domain": self.ens_domain,
            "skills": self.skills,
            "experience_years": self.experience_years,
            "bio": self.bio,
            "preferred_tokens": self.preferred_tokens,
            "nft_portfolio": self.nft_portfolio,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }