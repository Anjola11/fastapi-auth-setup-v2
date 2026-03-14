from pydantic import BaseModel, EmailStr
from datetime import datetime
import uuid 
from typing import Optional

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

class VerifyOTPInput(BaseModel):
    uid: uuid.UUID
    otp: str


class VerifyOTPResponse(BaseModel):
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
    email: str