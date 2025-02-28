import logging
from fastapi import FastAPI
from sqlmodel import Session, create_engine, SQLModel

from . import models

app = FastAPI()


logger = logging.getLogger('api')

engine = create_engine(f"sqlite:///database.db")

SQLModel.metadata.create_all(engine)

def get_session() -> Session:
    with Session(engine) as s:
        yield s

from . import routes