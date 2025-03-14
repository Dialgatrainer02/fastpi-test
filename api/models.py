import uuid
import datetime
from pydantic import UUID4, field_validator, EmailStr
from sqlmodel import SQLModel, Field
from typing import List, Optional, Any
from sqlalchemy import JSON

class Token(SQLModel):
    access_token: str
    token_type: str

class TokenData(SQLModel):
    username: str | None = None


class User(SQLModel, table=True): # can use inheritance here
    id: UUID4 = Field(default_factory=uuid.uuid4, primary_key=True)
    name: str = Field(index=True)
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


# todo add linked table for some kind of resource 