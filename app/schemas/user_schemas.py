import datetime as dt
from typing import Optional

from pydantic import BaseModel


class AuthToken(BaseModel):
    id: int
    user_id: str
    token: str


class OTPVerifyRequest(BaseModel):
    email: str
    otp: str


class TokenBlacklist(BaseModel):
    token: str


class UserBase(BaseModel):
    email: str

    class Config:
        from_attributes = True


class User(UserBase):
    id: int
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    is_subscribed: bool = False
    is_superadmin: bool
    is_deleted: bool

    class Config:
        from_attributes = True


class UserCreateRequest(UserBase):
    password: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None

    class Config:
        from_attributes = True


class UserLoginRequest(UserBase):
    password: str

    class Config:
        from_attributes = True


class UserSignupResponse(UserBase):
    id: int
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    access_token: str
    is_superadmin: bool
    created_at: dt.datetime


class UserLoginResponse(UserBase):
    id: int
    first_name: str
    last_name: str
    access_token: str


class UserChangePasswordRequest(UserBase):
    old_password: str
    new_password: str

    class Config:
        from_attributes = True


class UserResetPasswordRequest(UserBase):
    new_password: str
    otp: str

    class Config:
        from_attributes = True


class UserUpdateRequest(BaseModel):
    short_name: Optional[str] = None
    full_name: Optional[str] = None
    profile_pic: Optional[str] = None

    class Config:
        from_attributes = True
