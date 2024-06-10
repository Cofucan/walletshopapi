from typing import Optional
from datetime import datetime

from pydantic import BaseModel


class ProductBase(BaseModel):
    name: str
    description: str
    price: float
    stock: int


class ProductCreate(ProductBase):
    pass


class ProductRead(ProductBase):
    id: int
    currency_code: str
    is_deleted: bool
    created_at: datetime
    updated_at: Optional[datetime]


class ProductUpdate(ProductBase):
    pass
