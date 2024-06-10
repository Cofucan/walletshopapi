""" Main file for the API. """

import logging
import traceback
from contextlib import asynccontextmanager

import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# from admin import admin_app
from app.routes.auth import app as auth
from app.routes.products import app as products
from app.database import SessionLocal

# from api.db.database import create_database
from app.middleware.sessions import FlaskSessionMiddleware as SessionMiddleware
from app.settings import SECRET_KEY
from app.seeder import load_default_products
# from app.users import app as users

load_dotenv()

logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)


@asynccontextmanager
async def lifespan(_: FastAPI):
    db = SessionLocal()

    try:
        await load_default_products(db)
        yield
    finally:
        db.close()


app = FastAPI(lifespan=lifespan)
# app.mount(path="/admin", app=admin_app)

origins = ["https://api.cofucan.tech/walletshopapi", "*"]

# create_database()

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth)
app.include_router(products)

app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)


@app.get("/", tags=["Home"])
async def get_root(_: Request) -> dict:
    return {
        "message": "Welcome to WalletShop API Version 0.1",
        "url": "http://127:0:0:1/docs",
    }


@app.exception_handler(Exception)
async def generic_exception_handler(_, exc):
    if isinstance(exc, HTTPException):
        raise exc
    logger.error(exc, exc_info=True)
    traceback_str = traceback.format_exc()
    logger.error(traceback_str)
    message = f"Error: {exc}\n\nTraceback:\n```{traceback_str}```\n"

    logger.error(message)
    print(message)
    return JSONResponse(
        content={"detail": "Internal server error", "info": message},
        status_code=500,
    )


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0.0", port=8000, reload=True)
