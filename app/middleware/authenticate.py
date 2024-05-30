""" Authentication middleware. """

from datetime import datetime, timezone

from fastapi import Depends
from jose import jwt, JWTError
from sqlalchemy import orm

from app.database import get_db
from app.models import user_models
from app.schemas import user_schemas
from app.settings import SECRET_KEY, ALGORITHM
from app.services.auth_services import (
    oauth2_scheme,
)


def is_authenticated(
    token: str = Depends(oauth2_scheme), db: orm.Session = Depends(get_db)
) -> user_schemas.User | None:
    """Check if user is authenticated.

    Args:
        token (str): JWT token
        db (Session, optional): Database session. Defaults to Depends(get_db).

    Returns:
        User | None: User object if authenticated, else None
    """
    # Check if token is empty
    if not token:
        print("Error: Token is empty")
        return None

    # Check if token is in the blacklist
    if _ := (
        db.query(user_models.TokenBlacklist)
        .filter(user_models.TokenBlacklist.token == token)
        .first()
    ):
        print("Error: Token is blacklisted")
        return None

    # Validate JWT token
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("user_id")
        if user_id is None:
            print("Error: User id is not in payload")
            return None
        expire = payload.get("exp")
        if expire is None:
            print("Error: Token has no expiry")
            return None
        if datetime.now(timezone.utc) > datetime.fromtimestamp(
            expire, timezone.utc
        ):
            print("Error: Token has expired")
            return None
    except JWTError as jwe:
        print(f"Error: {jwe}")
        return None

    # Get user
    return (
        db.query(user_models.User)
        .filter(user_models.User.id == user_id)
        .first()
    )
