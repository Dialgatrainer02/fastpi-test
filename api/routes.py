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


@app.post("/token", response_model=Token, tags=["Auth"])
async def generate_token(form_data: Annotated[OAuth2PasswordRequestFormStrict, Depends()], s: Session = Depends(get_session)) -> Token:
    user = authenticate_user(s, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = create_token(
        data={"sub": user.name}, expires_delta=access_token_expires
    )
    return Token(access_token=token, token_type="bearer")


@app.post("/user", response_model=SafeUser, tags=["User"])
async def create_user(*, new_user: CreateUser, s: Session = Depends(get_session)):
    try:
        u = User(
            name=new_user.name,
            email=new_user.email,
            password=hash_password(new_user.password)
        )
        s.add(u)
        s.commit()
        s.refresh(u)
        return u
    except IntegrityError:
        raise HTTPException(status_code=400, detail="User already exists")


@app.get("/user", response_model=List[SafeUser], tags=['User'])
async def read_users(*, s: Session = Depends(get_session), token: Annotated[str, Depends(verify_token)]):
    try:
        return s.exec(select(User)).all()
    except:
        raise HTTPException(status_code=400, detail="Couldn't get users")


@app.patch("/user/{id}", response_model=SafeUser, tags=["User"])
async def update_user(*, id: UUID4, update_user: UpdateUser, s: Session = Depends(get_session), token: Annotated[str, Depends(verify_token)]):
    try:
        u = s.get(User, id)
        if update_user.name:
            u.name = update_user.name
        if update_user.password:
            u.password = hash_password(update_user.password)
        if update_user.email:
            u.email = update_user.email

        s.add(u)
        s.commit()
        s.refresh(u)
        return u
    except IntegrityError:
        raise HTTPException(status_code=400, detail="User already exists")


@app.put("/user/{id}", response_model=SafeUser, tags=["User"])
async def update_user(*, id: UUID4, create_user: CreateUser, s: Session = Depends(get_session), token: Annotated[str, Depends(verify_token)]):
    try:
        if None in (create_user.name, create_user.password, create_user.email):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Incomplete request"
            )
        u = s.get(User, id)
        u.name = create_user.name
        u.password = hash_password(create_user.password)
        u.email = create_user.email

        s.add(u)
        s.commit()
        s.refresh(u)
        return u
    except IntegrityError:
        raise HTTPException(status_code=400, detail="User already exists")


@app.delete("/user/{id}", status_code=status.HTTP_204_NO_CONTENT, tags=["User"])
async def delete_user(*, id: UUID4, s: Session = Depends(get_session), token: Annotated[str, Depends(verify_token)]):
    try:
        u = s.get(User, id)
        s.delete(u)
        s.commit()
        return
    except IntegrityError:
        raise HTTPException(status_code=400, detail="User doesn't exists")
