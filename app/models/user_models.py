""" User model. """
from typing import Optional
from uuid import uuid4

from sqlalchemy import (
    Column,
    String,
    Boolean,
    DateTime,
    Integer,
    func,
)
from sqlalchemy.orm import relationship

from app import database


class User(database.Base):
    """User model"""

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    first_name = Column(String(64), index=True)
    last_name = Column(String(64), index=True)
    email = Column(String(255), index=True)
    hashed_password = Column(String(255))
    is_superadmin = Column(Boolean, default=False)
    is_deleted = Column(Boolean, default=False)
    created_at: DateTime = Column(DateTime, server_default=func.now())
    updated_at: Optional[DateTime] = Column(DateTime, onupdate=func.now())

    # quotas = relationship("Quota", back_populates="user")
    # likes = relationship("CharacterLike", back_populates="user")


class TokenBlacklist(database.Base):
    """Token blacklist model"""

    __tablename__ = "token_blacklist"
    token = Column(String(255), primary_key=True, index=True)
    created_at: DateTime = Column(DateTime, server_default=func.now())


class OTPModel(database.Base):
    """OTP model"""

    __tablename__ = "otps"
    id = Column(String(255), primary_key=True, index=True, default=uuid4().hex)
    email = Column(String(255), unique=True, index=True)
    otp = Column(String(10), index=True)
    created_at: DateTime = Column(DateTime, server_default=func.now())
