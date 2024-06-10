""" Product endpoints. """

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.background import BackgroundTasks
from sqlalchemy import orm

from app.database import get_db
from app.middleware.authenticate import is_authenticated
from app.models import product_models
from app.schemas.product_schemas import (
    ProductRead,
    ProductCreate,
    ProductUpdate,
)

app = APIRouter(prefix="/api/v1/product", tags=["Products"])


@app.post("/", response_model=ProductRead)
async def create_product(
    product: ProductCreate, db: orm.Session = Depends(get_db)
):
    db_product = product_models.Product(**product.dict())
    db.add(db_product)
    db.commit()
    db.refresh(db_product)
    return db_product


@app.get("/{product_id}", response_model=ProductRead)
async def get_product(product_id: int, db: orm.Session = Depends(get_db)):
    product = (
        db.query(product_models.Product)
        .filter(product_models.Product.id == product_id)
        .first()
    )
    if product is None:
        raise HTTPException(status_code=404, detail="Product not found")
    return product


# Get app products
@app.get("/", response_model=list[ProductRead])
async def get_products(db: orm.Session = Depends(get_db)):
    products = db.query(product_models.Product).all()
    return products


@app.put("/{product_id}", response_model=ProductRead)
async def update_product(
    product_id: int,
    updated_product: ProductUpdate,
    db: orm.Session = Depends(get_db),
):
    product = (
        db.query(product_models.Product)
        .filter(product_models.Product.id == product_id)
        .first()
    )
    if product is None:
        raise HTTPException(status_code=404, detail="Product not found")
    for var, value in vars(updated_product).items():
        setattr(product, var, value) if value else None
    db.commit()
    return product


@app.delete("/{product_id}")
async def delete_product(product_id: int, db: orm.Session = Depends(get_db)):
    product = (
        db.query(product_models.Product)
        .filter(product_models.Product.id == product_id)
        .first()
    )
    if product is None:
        raise HTTPException(status_code=404, detail="Product not found")
    db.delete(product)
    db.commit()
    return {"detail": "Product deleted successfully"}
