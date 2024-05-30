""" This module is used to seed the database with default data. """
from app.models.product_models import Product
import uuid


async def load_default_products(db):
    """Load default products.

    Args:
        db (_type_): _description_
    """
    products = [
        {
            "name": "CPU",
            "description": "Central Processing Unit",
            "price": 200.0,
            "stock": 50,
        },
        {
            "name": "GPU",
            "description": "Graphics Processing Unit",
            "price": 500.0,
            "stock": 30,
        },
        {
            "name": "RAM",
            "description": "Random Access Memory",
            "price": 100.0,
            "stock": 100,
        },
        {
            "name": "SSD",
            "description": "Solid State Drive",
            "price": 150.0,
            "stock": 80,
        },
        {
            "name": "Motherboard",
            "description": "Main Circuit Board",
            "price": 300.0,
            "stock": 40,
        },
    ]

    for product in products:
        existing_product = (
            db.query(Product).filter(Product.name == product["name"]).first()
        )
        if not existing_product:
            new_product = Product(**product)
            db.add(new_product)

    db.commit()
