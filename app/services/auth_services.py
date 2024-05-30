""" Authentication services. """


import random
from datetime import datetime, timedelta, timezone
from jose import jwt
from passlib.context import CryptContext
from sqlalchemy import orm

from app.middleware.jwt_bearer import JWTBearer
from app.models import user_models
from app.settings import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES

oauth2_scheme = JWTBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str | bytes) -> str:
    """Hash password.

    Args:
        password (str | bytes): The password to hash.

    Returns:
        str: The hashed password.
    """
    return pwd_context.hash(password)


def verify_password(plain_password: str | bytes, hashed_password: str | bytes):
    """Verify password.

    Args:
        plain_password (str | bytes): The password provided by the user.
        hashed_password (str | bytes): The hashed password from the db.

    Returns:
        bool: True if the password matches, else False.
    """
    return pwd_context.verify(plain_password, hashed_password)


def authenticate_user(
    email: str, password: str, db: orm.Session
) -> user_models.User:
    """Authenticates a user by password.

    Args:
        email (str): The email provided by the user.
        password (str): The password provided by the user.
        db (orm.Session): The database session.

    Returns:
        user_models.User | bool: The user object if authenticated, else False.
    """
    if user := (
        db.query(user_models.User)
        .filter(user_models.User.email == email)
        .first()
    ):
        return (
            user if verify_password(password, str(user.hashed_password)) else False
        )
    else:
        return False


def create_access_token(
    data: dict, expires_delta: timedelta = timedelta(minutes=60 * 24)
) -> str:
    """Create access token.

    Args:
        data (dict): The data to encode in the token.
        expires_delta (timedelta, optional): The expiration time, from the time
            the token was created.
            Defaults to timedelta(minutes=60 * 24).

    Returns:
        str: The encoded JWT token.
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode["exp"] = expire
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_access_token(user_data: user_models.User, db: orm.Session) -> tuple:
    user = (
        db.query(user_models.User)
        .filter(user_models.User.email == user_data.email)
        .first()
    )
    if not user:
        # Create new user instance (excluding password from the response)
        created_user = user_models.User(
            short_name=user_data.display_name.lower(),
            full_name=f"{user_data.first_name.title()} {user_data.last_name.title()}",
            email=user_data.email,
        )
        db.add(created_user)
        db.commit()
        db.refresh(created_user)
        user = created_user

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    return user, create_access_token(
        data={"user_id": user.id}, expires_delta=access_token_expires
    )


# Generate OTP
def generate_otp():
    return "".join([str(random.randint(0, 9)) for _ in range(6)])
