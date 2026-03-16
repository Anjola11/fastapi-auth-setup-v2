from pydantic import BaseModel, EmailStr
from datetime import datetime
import uuid 
from typing import Optional
from enum import Enum

class OtpType(str, Enum):
    SIGNUP= "signup"
    FORGOT_PASSWORD= "forgot_password"


class User(BaseModel):
    uid: uuid.UUID
    first_name: str
    last_name: str
    user_name: str 
    email: EmailStr

class UserCreateInput(BaseModel):
    first_name: str
    last_name: str
    user_name: str 
    email: EmailStr
    password: str

class UserCreateResponse(BaseModel):
    success: bool
    message: str
    data: User

class VerifySignupOTPInput(BaseModel):
    uid: uuid.UUID
    otp: str


class VerifySignupOTPResponse(BaseModel):
    success: bool
    message: str
    data: dict = {}

class UserLoginInput(BaseModel):
    check_value: Optional[str] = None
    password: str

class UserLoginData(BaseModel):
    uid: uuid.UUID
    first_name: str
    last_name: str
    user_name: str 
    email: EmailStr
    email_verified: bool
    access_token: str
    refresh_token: str

class UserLoginResponse(BaseModel):
    success: bool
    message: str
    data: UserLoginData


class ResendOtpInput(BaseModel):
    email: EmailStr

class ForgotPasswordInput(BaseModel):
    email: EmailStr

class VerifyForgotPasswordInput(BaseModel):
    email: EmailStr
    otp: str

class ResetPasswordInput(BaseModel):
    email: EmailStr
    new_password: str

class VerifyForgotPasswordResponse(BaseModel):
    success: bool
    message: str
    data: dict = {}

class ResetPasswordResponse(BaseModel):
    success: bool
    message: str
    data: dict = {}