from . import app, get_session
from datetime import timedelta
from .models import *
from .utils import *
from typing import Annotated
from fastapi import Depends, HTTPException, status, Security
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
        data={"sub": str(user.id),"scopes": form_data.scopes}, expires_delta=access_token_expires
    )
    return Token(access_token=token, token_type="bearer")


@app.post("/user", response_model=SafeUser, tags=["User"])
async def create_user(*, new_user: CreateUser, s: Session = Depends(get_session)):
    """creates a new user

    Args:
        new_user (CreateUser): data for the new user
        s (Session, optional): db session. Defaults to Depends(get_session).

    Raises:
        HTTPException: user already exists

    Returns:
        _type_: SafeUser
    """
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


@app.get("/user", response_model=List[SafeUser], tags=['User'], description="list all users")
async def read_users(*, s: Session = Depends(get_session), token: Annotated[str, Depends(verify_token)]):
    """lists all users

    Args:
        token (Annotated[str, Depends): auth token 
        s (Session, optional): db session. Defaults to Depends(get_session).

    Raises:
        HTTPException: couldnt get users

    Returns:
        _type_: list(SafeUser)
    """
    try:
        return s.exec(select(User)).all()
    except:
        raise HTTPException(status_code=400, detail="Couldn't get users")


@app.patch("/user", response_model=SafeUser, tags=["User"])
async def update_user(*, update_user: UpdateUser, s: Session = Depends(get_session), user: Annotated[User, Security(verify_token, scopes=["user"])]):
    try:
        u = s.get(User, user.id)
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


@app.put("/user", response_model=SafeUser, tags=["User"])
async def update_user(*, create_user: CreateUser, s: Session = Depends(get_session), user: Annotated[User, Security(verify_token, scopes=["user"])]):
    try:
        if None in (create_user.name, create_user.password, create_user.email):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Incomplete request"
            )
        u = s.get(User, user.id)
        u.name = create_user.name
        u.password = hash_password(create_user.password)
        u.email = create_user.email

        s.add(u)
        s.commit()
        s.refresh(u)
        return u
    except IntegrityError:
        raise HTTPException(status_code=400, detail="User already exists")


@app.delete("/user", status_code=status.HTTP_204_NO_CONTENT, tags=["User"])
async def delete_user(*, s: Session = Depends(get_session), user: Annotated[User, Depends(verify_token)]):
    try:
        u = s.get(User, user.id)
        s.delete(u)
        s.commit()
        return
    except IntegrityError:
        raise HTTPException(status_code=400, detail="User doesn't exists")

@app.post("/booking", response_model=SafeBooking, tags=["Booking"])
async def create_Booking(*, new_Booking: CreateBooking, s: Session = Depends(get_session),user: Annotated[User, Depends(verify_token)]):
    try:
        db_booking = Booking.model_validate(new_Booking, update={"user_id": user.id}) 
        # logger.critical(token)
        # u = Booking(
        #     user_id = user_id,
        #     location = new_Booking.location,
        #     time = new_Booking.time

        # )
        s.add(db_booking)
        s.commit()
        s.refresh(db_booking)
        return db_booking
    except IntegrityError:
        raise HTTPException(status_code=400, detail="Booking already exists")


@app.get("/booking", response_model=List[SafeBooking], tags=['Booking'])
async def read_Bookings(*, s: Session = Depends(get_session), token: Annotated[str, Depends(verify_token)]):
    try:
        return s.exec(select(Booking)).all()
    except:
        raise HTTPException(status_code=400, detail="Couldn't get Bookings")


@app.patch("/booking/{id}", response_model=SafeBooking, tags=["Booking"])
async def update_Booking(*, id: UUID4, update_Booking: UpdateBooking, s: Session = Depends(get_session), token: Annotated[User, Depends(verify_token)]):
    try:
        b = s.get(Booking, id)
        update_Booking.sqlmodel_update(b)
        s.add(b)
        s.commit()
        s.refresh(b)
        return b
    except IntegrityError:
        raise HTTPException(status_code=400, detail="Booking already exists")


# @app.put("/Booking/{id}", response_model=SafeBooking, tags=["Booking"])
# async def update_Booking(*, id: UUID4, create_Booking: CreateBooking, s: Session = Depends(get_session), token: Annotated[str, Depends(verify_token)]):
#     try:
#         if None in (create_Booking.name, create_Booking.password, create_Booking.email):
#             raise HTTPException(
#                 status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
#                 detail="Incomplete request"
#             )
#         u = s.get(Booking, id)
#         u.name = create_Booking.name
#         u.password = hash_password(create_Booking.password)
#         u.email = create_Booking.email

#         s.add(u)
#         s.commit()
#         s.refresh(u)
#         return u
#     except IntegrityError:
#         raise HTTPException(status_code=400, detail="Booking already exists")


# @app.delete("/Booking/{id}", status_code=status.HTTP_204_NO_CONTENT, tags=["Booking"])
# async def delete_Booking(*, id: UUID4, s: Session = Depends(get_session), token: Annotated[str, Depends(verify_token)]):
#     try:
#         u = s.get(Booking, id)
#         s.delete(u)
#         s.commit()
#         return
#     except IntegrityError:
#         raise HTTPException(status_code=400, detail="Booking doesn't exists")

