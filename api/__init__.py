import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlmodel import Session, create_engine, SQLModel

from . import models

app = FastAPI(root_path="/api/v1") # can be expanded using apirouter

# origins = [
    # "http://localhost",
    # "http://localhost:8000",
    # "http://localhost:5500"
# ]
# 
app.add_middleware( 
    CORSMiddleware,
    allow_origins=["*"], # origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

logger = logging.getLogger('api')

engine = create_engine(f"sqlite:///database.db")

SQLModel.metadata.create_all(engine)

def get_session() -> Session:
    with Session(engine) as s:
        yield s

from . import routes