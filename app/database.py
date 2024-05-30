""" Database connection and session management. """
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from app.settings import (
    DB_TYPE,
    DB_NAME,
    DB_USER,
    DB_PASSWORD,
    DB_HOST,
    DB_PORT,
    DB_POOL_SIZE,
    DB_MAX_OVERFLOW,
    MYSQL_DRIVER,
)


if DB_TYPE == "mysql":
    DATABASE_URL = f"mysql+{MYSQL_DRIVER}://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
elif DB_TYPE == "postgresql":
    DATABASE_URL = (
        f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    )
else:
    DATABASE_URL = "sqlite:///./database.db"

if DB_TYPE == "sqlite":
    db_engine = create_engine(
        DATABASE_URL, connect_args={"check_same_thread": False}
    )
else:
    # db_engine = create_engine(DATABASE_URL)
    db_engine = create_engine(
        DATABASE_URL, pool_size=DB_POOL_SIZE, max_overflow=DB_MAX_OVERFLOW
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, expire_on_commit=False, bind=db_engine)

Base = declarative_base()


def create_database():
    return Base.metadata.create_all(bind=db_engine)


@contextmanager
def get_db_with_ctx_mgr():
    db = SessionLocal()
    try:
        yield db
    except:
        # if we fail somehow rollback the connection
        db.rollback()
        raise
    finally:
        db.close()


def get_db():
    with get_db_with_ctx_mgr() as db:
        yield db
