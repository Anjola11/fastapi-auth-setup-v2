import asyncio
from brevo import AsyncBrevo
from brevo.transactional_emails import (
    SendTransacEmailRequestSender,
    SendTransacEmailRequestToItem,
)
from brevo.core.api_error import ApiError
from src.config import Config
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATE_DIR = BASE_DIR / "templates"

template_env = Environment(
    loader=FileSystemLoader(TEMPLATE_DIR)
)

class EmailServices:
    def __init__(self):
        self.client = AsyncBrevo(api_key=Config.BREVO_API_KEY)
        self.sender_name = Config.BREVO_SENDER_NAME
        self.sender_email = Config.BREVO_EMAIL

    

    def render_template(self, template_name: str, payload: dict ={}):
        try:
            template = template_env.get_template(f"{template_name}.html")
            return template.render(**payload)
        except Exception as err:
            print(f"Error reding template ' {template_name}': {err}")
            raise err
    


    async def send_email(self, to_email: str, subject: str, html_content: str, text_content: str):
        try:
            await self.client.transactional_emails.send_transac_email(
                subject=subject,
                html_content=html_content,
                text_content=text_content,
                sender=SendTransacEmailRequestSender(
                    name=self.sender_name,
                    email=self.sender_email
                ),
                to=[
                    SendTransacEmailRequestToItem(
                        email=to_email,
                    )
                ],
            )
        except ApiError as e:
            print(e.status_code)
            print(e.body)

    async def send_email_verification_otp(self, user_email: str, otp_code: str, user_first_name: str):
        subject = 'Test - Email Verification Code'
        html_content = self.render_template('email-verification-otp', {
                'user_first_name': user_first_name,
                'otpCode': otp_code,
                'expiryTime': '10 minutes'
            }
        )
        text_content = f"""Hello {user_first_name},
Your Planit verification code is: {otp_code}
This code will expire in 10 minutes. Please do not share this code with anyone.
If you didn't request this code, please ignore this email.
Best regards,
The test Team"""
        return await self.send_email(user_email, subject, html_content, text_content)

    async def send_welcome_email(self, user_email: str, user_first_name: str):
        subject = "Test - Welcome to test"
        html_content = self.render_template(
            'welcome-email',
            {
                'user_first_name': user_first_name
            }
        )
        text_content = f"""Welcome to Test, {user_first_name}!
        Thank you for verifying your email. We're excited to have you on board! Test helps you manage test, test, and everything in between.
        Best regards,
        The Test Team"""

        return await self.send_email(user_email, subject, html_content, text_content)


