from sqlmodel import SQLModel, Field, Column
from pydantic import EmailStr
from datetime import datetime, timezone, timedelta
import uuid
import sqlalchemy.dialects.postgresql as pg

def utc_now():
    return datetime.now(timezone.utc)

class User(SQLModel, table=True):

    __tablename__ = "users"

    uid: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    first_name: str
    last_name: str
    user_name: str = Field(unique=True, index=True)
    email: EmailStr = Field(unique=True, index=True)
    password_hash: str = Field(exclude=True)
    email_verified: bool = Field(
        default=False
    )
    created_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(pg.TIMESTAMP(timezone=True))
    )


def get_expiry(time: int = 10):
    return datetime.now(timezone.utc) + timedelta(minutes=time)

class SignupOtp(SQLModel, table=True):
    __tablename__ = "signup_otp"
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    uid: uuid.UUID = Field(
        foreign_key="users.uid"
        )
    otp_hash: str
    created_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(pg.TIMESTAMP(timezone=True))
    )
    expires: datetime = Field(
        default_factory=get_expiry,
        sa_column=Column(pg.TIMESTAMP(timezone=True), nullable=False)
    )

class ForgotPasswordOtp(SQLModel, table=True):
    __tablename__ = "forgot_password_otp"
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    uid: uuid.UUID = Field(foreign_key="users.uid")
    otp_hash: str
    created_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(pg.TIMESTAMP(timezone=True))
    )
    expires: datetime = Field(
        default_factory=get_expiry,
        sa_column=Column(pg.TIMESTAMP(timezone=True), nullable=False)
    )

class AllowedResetPassword(SQLModel, table=True):
    __tablename__ = "allowed_reset_password"
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    uid: uuid.UUID = Field(foreign_key="users.uid")
    expires: datetime = Field(
        default_factory=get_expiry,
        sa_column=Column(pg.TIMESTAMP(timezone=True), nullable=False)
    )