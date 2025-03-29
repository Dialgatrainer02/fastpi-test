import logging
import jwt
from sqlmodel import select, Session
from . import get_session
from .models import *
from fastapi import Depends, HTTPException, status
from typing import Annotated
import bcrypt
from fastapi.security import OAuth2PasswordBearer, SecurityScopes
from datetime import timedelta, timezone

logger = logging.getLogger('utils')

SECRET_KEY = "testing_purposes"
ALGORITHM = "HS256"


oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="token", scopes={"user": "permits user resources"})


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
        expire = datetime.datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"iss": "test-api"})
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_token(token: Annotated[str, Depends(oauth2_scheme)], security_scopes: SecurityScopes,session: Session = Depends(get_session)) -> bool:
    if security_scopes.scopes:
        authenticate_value = f'Bearer scope="{security_scopes.scope_str}"'
    else:
        authenticate_value = "Bearer"
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": authenticate_value},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = uuid.UUID(payload.get("sub"))
        issuer = payload.get('iss')
        scopes = str(payload.get('scopes')) # have to type cast to string otherwise validation errors
        if user_id is None:
            raise credentials_exception
        if issuer is None:
            raise credentials_exception
        if issuer != "test-api":
            raise credentials_exception
        token_data = TokenData(user_id=user_id,scopes=[scopes])
        user = session.get(User, user_id)
        if user is None:
            raise credentials_exception
        for scope in security_scopes.scopes:
            if scope not in token_data.scopes:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Not enough permissions",
                    headers={"WWW-Authenticate": authenticate_value},
                )
    except jwt.InvalidTokenError:
        raise credentials_exception
    return True




def get_user(s: Session, username: str) -> User:
    return s.exec(select(User).where(User.name == username)).first()

