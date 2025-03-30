import uuid
import datetime
from pydantic import UUID4, field_validator, EmailStr, ConfigDict 
from sqlmodel import SQLModel, Field, Relationship, Column
from typing import List, Optional, Any
from sqlalchemy import JSON

class Token(SQLModel):
    access_token: str
    token_type: str

class TokenData(SQLModel):
    user_id: UUID4 | None = None
    scopes: list[str] = []


class User(SQLModel, table=True): # can use inheritance here
    id: UUID4 = Field(default_factory=uuid.uuid4, primary_key=True)
    name: str = Field(index=True, unique=True)
    email: EmailStr
    password: str
    # scope: List[str] | None = Field(sa_type=JSON)


class CreateUser(SQLModel):
    name: str
    email: EmailStr
    password: str

class UpdateUser(SQLModel):
    name: Optional[str]
    email: Optional[EmailStr]
    password: Optional[str]

class SafeUser(SQLModel):
    id: str
    name: str
    email: EmailStr

    @field_validator("id", mode="before")
    @classmethod
    def id_to_str(cls, value: any) -> str:
        return str(value) 

class Location(SQLModel):
    postcode: str
    city: str
    address: str

class Booking(SQLModel, table=True): # can use inheritance here
    id: UUID4 = Field(default_factory=uuid.uuid4, primary_key=True)
    user_id: UUID4 = Field(foreign_key="user.id")
    # user: User = Relationship(back_populates="booking")
    location: Location = Field(sa_column=Column(JSON))
    time: str
    # scope: List[str] | None = Field(sa_type=JSON)

    # hacky workaround as nested models dont work yet 
    @field_validator("location", mode="after")
    @classmethod
    def location_validator(cls, value: Location) -> dict:
        return dict(value)



    


class CreateBooking(SQLModel):
    # user_id: UUID4
    location: Location
    time: str

class UpdateBooking(SQLModel):
    location: Optional[Location]
    time: Optional[str]

class SafeBooking(SQLModel):
    id: str
    location: Location
    time: str

    @field_validator("id", mode="before")
    @classmethod
    def id_to_str(cls, value: any) -> str:
        return str(value) 

