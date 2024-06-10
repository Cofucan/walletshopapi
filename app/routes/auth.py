""" Authentication endpoints. """

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.background import BackgroundTasks
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordBearer
from fastapi_sso.sso.github import GithubSSO
from fastapi_sso.sso.google import GoogleSSO
from sqlalchemy import orm

from app.database import get_db
from app.middleware.authenticate import is_authenticated
from app.models import user_models
from app.schemas import user_schemas
from app.services.auth_services import (
    authenticate_user,
    create_access_token,
    generate_otp,
    get_access_token,
    hash_password,
    pwd_context,
)
from app.services.messaging_services import send_otp, send_welcome_mail
from app.settings import ACCESS_TOKEN_EXPIRE_MINUTES, OTP_EXPIRE_MINUTES, FRONTEND_URL, GOOGLE_CLIENT_ID, \
    GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI, GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, GITHUB_REDIRECT_URI

auth_router = APIRouter(prefix="/auth", tags=["Authentication"])

google_sso = GoogleSSO(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI)
github_sso = GithubSSO(GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, GITHUB_REDIRECT_URI)

app = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# Signup endpoint
@app.post("/signup", response_model=user_schemas.UserSignupResponse)
async def signup(
        payload: user_schemas.UserCreateRequest,
        bg_tasks: BackgroundTasks,
        db: orm.Session = Depends(get_db),
):
    """Signup endpoint.

    Args:
        payload (UserCreate): User payload to create user.
        bg_tasks (BackgroundTasks): Background tasks.
        db (Session, optional): Database session. Defaults to Depends(get_db).

    Raises:
        HTTPException: If user already exists.

    Returns:
        User: Created user.
    """
    if user := (
            db.query(user_models.User)
            .filter(user_models.User.email == payload.email)
            .first()
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User already exists",
        )

    # Hash the password
    hashed_password = pwd_context.hash(payload.password)

    # Create new user instance (excluding password from the response)
    created_user = user_models.User(
        first_name=payload.first_name,
        last_name=payload.last_name,
        email=payload.email,
        hashed_password=hashed_password,
    )

    db.add(created_user)
    db.commit()
    db.refresh(created_user)

    # Send welcome email
    bg_tasks.add_task(
        send_welcome_mail,
        created_user.email,
        f"{created_user.first_name} {created_user.last_name}"
    )

    # Generate access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"user_id": created_user.id}, expires_delta=access_token_expires
    )

    return {
        "id": created_user.id,
        "email": created_user.email,
        "first_name": created_user.first_name,
        "last_name": created_user.last_name,
        "access_token": access_token,
        "is_superadmin": created_user.is_superadmin,
        "created_at": created_user.created_at,
    }


# Login endpoint
@app.post("/login", response_model=user_schemas.UserLoginResponse)
async def login_for_access_token(
        payload: user_schemas.UserLoginRequest,
        db: orm.Session = Depends(get_db),
):
    """Login endpoint.

    Args:
        payload (UserLogin): User payload to login.
        db (Session, optional): Database session. Defaults to Depends(get_db).

    Raises:
        HTTPException: If user is not authenticated.

    Returns:
        UserLoginResponse: User login response.
    """
    user = authenticate_user(payload.email, payload.password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # If user is deleted
    if user.is_deleted:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is deleted",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"user_id": user.id}, expires_delta=access_token_expires
    )

    return {
        "id": user.id,
        "email": user.email,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "access_token": access_token,
    }


# Change password
@app.post("/change_password")
async def change_password(
        payload: user_schemas.UserChangePasswordRequest,
        current_user: user_schemas.User = Depends(is_authenticated),
        db: orm.Session = Depends(get_db),
):
    """Change password endpoint.

    Args:
        payload (UserChangePassword): User payload to change password.
        current_user (User, optional): Current user. Defaults to Depends().
        db (Session, optional): Database session. Defaults to Depends(get_db).

    Raises:
        HTTPException: If user is not authenticated.

    Returns:
        Dict[str, str]: Response message.
    """
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="You need to be logged in to change password",
        )

    # Check if old password is correct
    user = authenticate_user(current_user.email, payload.old_password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect old password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Hash the new password
    hashed_password = pwd_context.hash(payload.new_password)

    # Update the user's password
    user.hashed_password = hashed_password
    user.updated_at = datetime.now(timezone.utc)
    db.commit()

    return {"detail": "Password changed successfully"}


# Forgot password
@app.post("/forgot_password")
async def forgot_password(
        payload: user_schemas.UserBase,
        db: orm.Session = Depends(get_db),
):
    """Forgot password endpoint.

    Args:
        payload (UserForgotPassword): User payload to forgot password.
        db (Session, optional): Database session. Defaults to Depends(get_db).

    Returns:
        Dict[str, str]: Response message.
    """
    # Check if user exists
    user = (
        db.query(user_models.User)
        .filter(user_models.User.email == payload.email)
        .first()
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User does not exist",
        )

    # Generate OTP
    code = generate_otp()

    # Check if there's a pending OTP
    otp = (
        db.query(user_models.OTPModel)
        .filter(user_models.OTPModel.email == payload.email)
        .first()
    )
    if otp:
        otp.otp = code
        otp.created_at = datetime.now(timezone.utc)
    else:
        otp = user_models.OTPModel(email=payload.email, otp=code)
        db.add(otp)

    db.commit()

    # Send OTP to user
    send_otp(payload.email, otp.otp, "Here is your OTP")

    return {"detail": "OTP sent successfully"}


# Reset password
@app.post("/reset_password")
async def reset_password(
        payload: user_schemas.UserResetPasswordRequest,
        db: orm.Session = Depends(get_db),
):
    """Reset password endpoint.

    Args:
        payload (UserResetPassword): User payload to reset password.
        db (Session, optional): Database session. Defaults to Depends(get_db).

    Returns:
        Dict[str, str]: Response message.
    """
    # Check if user exists
    user = (
        db.query(user_models.User)
        .filter(user_models.User.email == payload.email)
        .first()
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User does not exist",
        )

    # Check if OTP exists
    otp = (
        db.query(user_models.OTPModel)
        .filter(user_models.OTPModel.email == payload.email)
        .first()
    )
    if not otp:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="OTP does not exist",
        )

    # Check if OTP is expired
    if otp.created_at + timedelta(minutes=OTP_EXPIRE_MINUTES) < datetime.now(
            timezone.utc
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OTP expired",
        )

    # Check if OTP is correct
    if otp.otp != payload.otp:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect OTP",
        )

    # Hash the new password
    hashed_password = pwd_context.hash(payload.new_password)

    # Update the user's password
    user.hashed_password = hashed_password
    user.updated_at = datetime.now(timezone.utc)
    db.delete(otp)
    db.commit()

    return {"detail": "Password reset successfully"}


# Logout endpoint which will invalidate the token
@app.post("/logout")
async def invalidate_access_token(
        access_token: str = Depends(oauth2_scheme),
        _: user_schemas.User = Depends(is_authenticated),
        db: orm.Session = Depends(get_db),
):
    """Logout endpoint.

    Args:
        access_token (str, optional): Access token.
            Defaults to Depends(oauth2_scheme).
        (User, optional): Current user. Defaults to Depends().
        db (Session, optional): Database session. Defaults to Depends(get_db).
    """
    if not access_token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authentication credentials were not provided",
        )
    token = user_models.TokenBlacklist(token=access_token)
    db.add(token)
    db.commit()
    return {"detail": "Logged out successfully"}


# Endpoint to generate and send OTP to the user
@app.post("/otp/generate")
async def generate_and_send_otp(
        payload: user_schemas.UserBase,
        db: orm.Session = Depends(get_db),
):
    """Generate OTP endpoint.

    Args:
        payload (UserBase): The user's email
        db (Session, optional): Database session. Defaults to Depends(get_db).

    Returns:
        Dict[str, str]: Response message.
    """
    # Check if user exists
    user = (
        db.query(user_models.User)
        .filter(user_models.User.email == payload.emails)
        .first()
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User does not exist",
        )

    code = generate_otp()

    # Check if there's a pending OTP
    otp = (
        db.query(user_models.OTPModel)
        .filter(user_models.OTPModel.email == payload.email)
        .first()
    )
    if otp:
        otp.otp = code
        otp.created_at = datetime.now(timezone.utc)
    else:
        otp = user_models.OTPModel(email=payload.email, otp=code)
        db.add(otp)

    db.commit()

    # Send OTP to user
    send_otp(payload.email, otp, "Here is your OTP")
    return {"detail": "OTP sent successfully"}


# Google login
@app.get("/login/google")
async def google_login():
    """Generate login url and redirect"""
    with google_sso:
        return await google_sso.get_login_redirect()


# Process login request from google and return user data with access token
@app.get("/login/google/callback", response_model=user_schemas.UserLoginResponse)
async def google_login_callback(
        request: Request,
        background_tasks: BackgroundTasks,
        db: orm.Session = Depends(get_db),
):
    """
    Process login request from google and return user data with access token.

    Args:
        request (Request): Request object containing auth code from Google.
        background_tasks (BackgroundTasks): Background tasks.
        db (Session, optional): Database session. Defaults to Depends(get_db).

    Returns:
        UserLoginResponse: User login response.
    """
    with google_sso:
        user_data = await google_sso.verify_and_process(request)
        user, access_token = get_access_token(user_data, db)

    if not user_data:
        raise HTTPException(status_code=400, detail="Failed to Login to Google")

    user_email = user.email
    display_name = user.first_name.lower()

    # Check if a user with the given email exists
    current_user = db.query(user_models.User).filter_by(email=user_email).first()

    # Add user to database if user doesn't exist
    if not current_user:
        password = hash_password(user_email)
        current_user = user_models.User(
            email=user_email,
            first_name=display_name,
            hashed_password=password,
        )

        db.add(current_user)
        db.commit()
        db.refresh(current_user)

        background_tasks.add_task(
            send_welcome_mail, current_user.email, current_user.username
        )

    # Construct the redirect URL with query parameters
    redirect_url = f"{FRONTEND_URL}?success=true&token={access_token}"
    # Redirect to the constructed URL
    return RedirectResponse(redirect_url)


# GitHub login
@app.get("/login/github")
async def github_login():
    """Generate login url and redirect"""
    with github_sso:
        return await github_sso.get_login_redirect()


# Process login request from GitHub and return user data with access token
@app.get("/login/github/callback", response_model=user_schemas.UserLoginResponse)
async def github_login_callback(
        request: Request,
        db: orm.Session = Depends(get_db),
):
    """
    Process login request from GitHub and return user data with access token.

    Args:
        request (Request): Request object containing auth code from GitHub.
        db (Session, optional): Database session. Defaults to Depends(get_db).

    Returns:
        UserLoginResponse: User login response.
    """
    with github_sso:
        user_data = await github_sso.verify_and_process(request)
        _, access_token = get_access_token(user_data, db)
        redirect_url = f"{FRONTEND_URL}/magic-login?success=true&token={access_token}"
        return RedirectResponse(redirect_url)


# Delete user
@app.delete("/close_account")
async def delete_user(
        current_user: user_schemas.User = Depends(is_authenticated),
        db: orm.Session = Depends(get_db),
):
    """Delete user endpoint.

    Args:
        current_user (User, optional): Current user. Defaults to Depends().
        db (Session, optional): Database session. Defaults to Depends(get_db).

    Raises:
        HTTPException: If user is not authenticated.

    Returns:
        Dict[str, str]: Response message.
    """
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="You need to be logged in to delete your account",
        )

    # Delete user (soft deletion)
    current_user.is_deleted = True
    db.commit()

    return {"detail": "Account deleted successfully"}
