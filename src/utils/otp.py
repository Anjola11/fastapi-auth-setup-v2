import secrets 
import string
import bcrypt


def generate_otp(length: int = 6) -> str:
    otp = "".join(secrets.choice(string.digits) for i in range(length))

    return otp


def generate_otp_hash(otp: str ) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(otp.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_otp_hash(otp: str, otp_hash: str) -> bool:
    return bcrypt.checkpw(otp.encode('utf-8'), otp_hash.encode('utf-8'))
