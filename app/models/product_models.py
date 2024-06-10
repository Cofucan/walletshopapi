""" Product model. """
from typing import Optional
from uuid import uuid4

from sqlalchemy import (
    Column,
    String,
    Float,
    Integer,
    Boolean,
    DateTime,
    func,
)
from sqlalchemy.orm import relationship

from app import database


class Product(database.Base):
    """Product model"""

    __tablename__ = "products"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), index=True)
    description = Column(String(255))
    price = Column(Float)
    stock = Column(Integer)
    currency_code = Column(String(3), default="USD")
    is_deleted = Column(Boolean, default=False)
    created_at: DateTime = Column(DateTime, server_default=func.now())
    updated_at: Optional[DateTime] = Column(DateTime, onupdate=func.now())
