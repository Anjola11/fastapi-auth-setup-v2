from sqlmodel.ext.asyncio.session import AsyncSession
from src.auth.models import User
from sqlmodel import select
from src.auth.schemas import (
    UserCreateInput,
    VerifyOTPInput,
    UserLoginInput,
    ResendOtpInput
    )
from fastapi import HTTPException, status, Depends
from sqlalchemy.exc import DatabaseError
from src.utils.auth import generate_password_hash,verify_password_hash, create_token, TokenType
from src.auth.models import SignupOtp
from src.utils.otp import generate_otp, generate_otp_hash, verify_otp_hash
import uuid
from enum import Enum
from datetime import datetime, timezone
from src.emailServices.main import EmailServices

def get_email_services() -> EmailServices:
    return EmailServices()

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

        if otp.expires <= datetime.now(timezone.utc):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Otp expired"
                )
        
        verified_otp = verify_otp_hash(user_input.otp, otp.otp_hash)
        if otp and verified_otp:

            user_statement = select(User).where(User.uid == user_input.uid)
            user_result = await session.exec(user_statement)
            user = user_result.first()

            user.email_verified = True

            await session.delete(otp)
            try:
                session.add(user)
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
    
    async def resend_otp(self, user_input: ResendOtpInput, session: AsyncSession):

        statement = select(User).where(User.email == user_input.email)
        result = await session.exec(statement)
        user = result.first()


        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail = "Invalid Credentials"
            )
        

        
        otp_statement = select(SignupOtp).where(SignupOtp.uid == user.uid).order_by(SignupOtp.created_at.desc()).limit(1)

        result = await session.exec(otp_statement)
        old_otp = result.first()

        if not old_otp:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No pending OTP found"
            )
        if old_otp.expires > datetime.now(timezone.utc):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="please verify with the code sent to your email"
            )
        
        new_otp_code = generate_otp()
        new_otp_hash = generate_otp_hash(new_otp_code)
        new_otp = SignupOtp(
            uid= user.uid,
            otp_hash= new_otp_hash
        )


        
        try:
            await session.delete(old_otp)
            session.add(new_otp)
            await session.commit()

            return {
                **user.model_dump(exclude={"password_hash"}),
                "new_otp_code": new_otp_code
            }

        except DatabaseError:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="failed to send otp"
            )
    
    async def login(self, user_input: UserLoginInput, session: AsyncSession):

        if not user_input.check_value:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="enter either username or email"
            )

        
        statement = select(User).where((User.email == user_input.check_value) | (User.user_name == user_input.check_value))
        result = await session.exec(statement)

        user = result.first()

        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Credentials"
            )

        verified_password = verify_password_hash(user_input.password, user.password_hash)

        
        if verified_password:

            if not user.email_verified:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="please, verify your email to login"
                )
        

            access_token = create_token(user, TokenType.ACCESS)
            refresh_token = create_token(user, TokenType.REFRESH)

            response = {
                **user.model_dump(exclude={"password_hash"}),
                "access_token": access_token,
                "refresh_token": refresh_token
            }
            return response
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Credentials"
        )
       