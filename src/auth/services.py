from sqlmodel.ext.asyncio.session import AsyncSession
from src.auth.models import User
from sqlmodel import select
from src.auth.schemas import (
    UserCreateInput,
    VerifyOTPInput
    )
from fastapi import HTTPException, status
from sqlalchemy.exc import DatabaseError
from src.utils.auth import generate_password_hash
from src.auth.models import SignupOtp
from src.utils.otp import generate_otp_hash, verify_otp_hash
import uuid
from enum import Enum
from datetime import datetime, timezone

class CheckUserMethod(str, Enum):
    EMAIL = "email"
    USER_NAME = "user_name"



class AuthServices():
    async def check_user_exist(self, check_value:str, session:AsyncSession, check_method: CheckUserMethod):
        if check_method == CheckUserMethod.EMAIL:
            check_field  = "email"
        elif check_method == CheckUserMethod.USER_NAME:
            check_field  = "user_name"

        column = getattr(User, check_field)
        statement = select(User).where(column == check_value)
        result = await session.exec(statement)
        user = result.first()

        if user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail = f"An account with these details already exists"
            )
        return None
    
    async def create_user(self,user_input: UserCreateInput, session: 
        AsyncSession ):
        await self.check_user_exist(user_input.email, session, CheckUserMethod.EMAIL)
        await self.check_user_exist(user_input.user_name, session, CheckUserMethod.USER_NAME)

        password_hash = generate_password_hash(user_input.password)

        new_user = User(
            first_name = user_input.first_name,
            last_name = user_input.last_name,
            user_name = user_input.user_name,
            email = user_input.email,
            password_hash = password_hash
        )
        
        try:
            session.add(new_user)
            await session.commit()
            await session.refresh(new_user)
            return new_user
        
        except DatabaseError:
            await session.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="account creation failed, try again"
            )
        
    async def save_otp(self, otp:str, uid: uuid.UUID, session:AsyncSession):
        otp_hash = generate_otp_hash(otp)
        new_otp = SignupOtp(
            uid= uid,
            otp_hash=otp_hash
        )

        try:
            session.add(new_otp)
            await session.commit()
            await session.refresh(new_otp)
            return new_otp
        
        except DatabaseError:
            await session.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="otp generation failed, try again"
            )
        
    async def verify_otp(self, user_input: VerifyOTPInput, session: AsyncSession):
        otp_statement = select(SignupOtp).where(SignupOtp.uid == user_input.uid).order_by(SignupOtp.created_at.desc()).limit(1)

        otp_result = await session.exec(otp_statement)
        otp = otp_result.first()

        if not otp:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired OTP"
            )

        verified_otp = verify_otp_hash(user_input.otp, otp.otp_hash)
        if otp and verified_otp:
            if otp.expires <= datetime.now(timezone.utc):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Otp expired"
                )

            user_statement = select(User).where(User.uid == user_input.uid)
            user_result = await session.exec(user_statement)
            user = user_result.first()

            user.email_verified = True

            await session.delete(otp)
            try:
                await session.commit()
                return {
                    "message": "Email verified successfully",
                    "user_email": user.email,
                    "user_first_name": user.first_name
                    }
            except DatabaseError:
                await session.rollback()
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="verificaton failed, try again"
                )
        
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid"
        )