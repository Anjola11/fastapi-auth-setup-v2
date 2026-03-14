import bcrypt
import jwt
from datetime import datetime, timedelta, timezone
from enum import Enum
from src.auth.models import User
from src.config import Config

access_expiry = timedelta(hours=4)
refresh_expiry = timedelta(days=2)

class TokenType(str, Enum):
    ACCESS = "access"
    REFRESH = "refresh"

def generate_password_hash(password: str ) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password_hash(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))

def create_token(user_data: User, type: TokenType) -> str:

    current_time = datetime.now(timezone.utc)

    payload = {
        'iat': current_time,
        'sub': str(user_data.uid),
        'type': type,
    }

    payload['exp'] = current_time + refresh_expiry

    if type == TokenType.ACCESS:
        payload['email_verified'] = user_data.email_verified
        payload['user_name'] = user_data.user_name
        payload['exp'] = current_time + access_expiry


    token = jwt.encode(
        payload=payload,
        key= Config.JWT_KEY,
        algorithm=Config.JWT_ALGORITHM
    )

    return token

    
    
    


