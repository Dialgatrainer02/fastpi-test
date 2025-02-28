import logging
import jwt
from sqlmodel import select, Session
from . import get_session
from .models import *
import bcrypt
from fastapi.security import OAuth2PasswordBearer
from datetime import timedelta

logger = logging.getLogger('utils')

SECRET_KEY = "testing_purposes"
ALGORITHM = "HS256"


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(
        bytes(password, encoding="utf-8"),
        bcrypt.gensalt(),
    )

def verify_password(plain_password: str, hashed_password: bytes) -> bool:
    return bcrypt.checkpw(
        bytes(plain_password, encoding="utf-8"),
        hashed_password,
    )

def authenticate_user(s: Session, username: str, password: str) -> User | bool:
    u = get_user(s, username)
    if not u: 
        return False
    if not verify_password(password, u.password):
        return False
    return u
    
def create_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_user(s: Session, username: str) -> User:
    return s.exec(select(User).where(User.name == username)).first()

