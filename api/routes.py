from . import app, get_session
from datetime import timedelta
from .models import *
from .utils import *
from typing import Annotated
from fastapi import Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from fastapi.security import OAuth2PasswordRequestFormStrict

ACCESS_TOKEN_EXPIRE_MINUTES = 30

access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

@app.post("/token", response_model=Token, tags=["auth"])
async def create_token(form_data: Annotated[OAuth2PasswordRequestFormStrict, Depends()], s: Session = Depends(get_session)) -> Token:
    user = authenticate_user(s, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = create_token(
        data={"sub": user.name, "iss": "test-api"}, expires_delta=access_token_expires
    )
    return Token(access_token=token, token_type="bearer")


@app.post("/user", response_model=CreateUser, tags=["Auth"])
async def create_user(*,new_user: CreateUser, s: Session = Depends(get_session)):
    try: 
        u = User(
            name = new_user.name,
            email = new_user.email,
            password = hash_password(new_user.password)
        )
        s.add(u)
        s.commit()
        s.refresh(u)
        return u 
    except IntegrityError:
        raise HTTPException(status_code=400, detail="User already exists")

@app.patch("/user", response_model=CreateUser, tags=["Auth"])
async def update_user(*,id: UUID4,update_user: UpdateUser, s: Session = Depends(get_session), token: Annotated[str, Depends(oauth2_scheme)]):
    try: 
        u = s.get(User, id)

        s.add(u)
        s.commit()
        s.refresh(u)
        return u 
    except IntegrityError:
        raise HTTPException(status_code=400, detail="User already exists")
