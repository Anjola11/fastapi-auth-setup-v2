from fastapi import APIRouter, Depends, BackgroundTasks, status
from sqlmodel.ext.asyncio.session import AsyncSession
from src.auth.schemas import (
    UserCreateInput,
    UserCreateResponse,
    VerifyOTPInput,
    VerifyOTPResponse,
    UserLoginInput,
    UserLoginResponse,
    ResendOtpInput
)
from src.auth.models import User
from src.db.main import get_session
from src.auth.services import AuthServices
from src.utils.otp import generate_otp
from src.emailServices.main import EmailServices

auth_router = APIRouter()


def  get_email_services() -> EmailServices:
    return EmailServices()

def get_auth_services() -> AuthServices:
    return AuthServices()



@auth_router.post('/signup', response_model=UserCreateResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    user_input: UserCreateInput, 
    background_tasks: BackgroundTasks, 
    session: AsyncSession = Depends(get_session),
    auth_services: AuthServices = Depends(get_auth_services),
    email_services: EmailServices = Depends(get_email_services)
    ):

    new_user = await auth_services.create_user(user_input, session)

    new_otp = generate_otp()
    await auth_services.save_otp(new_otp, new_user.uid, session)

    background_tasks.add_task(
        email_services.send_email_verification_otp,
        new_user.email,
        new_otp,
        new_user.first_name
    )

    return {
        "success": True,
        "message": "signup successful, an otp has been sent to your email to verify your account",
        "data": new_user
    }

@auth_router.post('/verify-otp', response_model=VerifyOTPResponse, status_code=status.HTTP_200_OK)
async def verify_otp(
    user_input: VerifyOTPInput, 
    background_tasks: BackgroundTasks, 
    session: AsyncSession = Depends(get_session),
    auth_services: AuthServices = Depends(get_auth_services),
    email_services: EmailServices = Depends(get_email_services)
    ):

    verified_otp = await auth_services.verify_otp(user_input, session)

    if verified_otp:
        background_tasks.add_task(
            email_services.send_welcome_email,
            verified_otp.get('user_email'),
            verified_otp.get('user_first_name')
        )

        return {
            "success": True,
            "message": "otp verified successfully",
            "data": {}
        }
    
@auth_router.post("/resend-otp", status_code=status.HTTP_200_OK)
async def resend_otp(
    user_input: ResendOtpInput,
    background_tasks: BackgroundTasks,
    session: AsyncSession= Depends(get_session),
    auth_services: AuthServices = Depends(get_auth_services),
    email_services: EmailServices = Depends(get_email_services),
    
):
    resend_otp = await auth_services.resend_otp(user_input,session)

    background_tasks.add_task(
        email_services.send_email_verification_otp,
        resend_otp.get('email'),
        resend_otp.get('new_otp_code'),
        resend_otp.get('first_name')
    )

    return {
            "success": True,
            "message": "otp sent successfully",
            "data": {}
        }

    
    
@auth_router.post("/login", response_model=UserLoginResponse, status_code=status.HTTP_200_OK)
async def login(
    user_input: UserLoginInput, 
    session: AsyncSession= Depends(get_session),
    auth_services: AuthServices = Depends(get_auth_services)):
    user_login = await auth_services.login(user_input, session)

    return {
        "success": True,
        "message": "user logged in successfully",
        "data": user_login
    }