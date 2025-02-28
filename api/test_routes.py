import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine
from sqlmodel.pool import StaticPool

from . import get_session, app
from .utils import hash_password


@pytest.fixture(name="session")
def session_fixture():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


@pytest.fixture(name="client")
def client_fixture(session: Session):
    def get_session_override():
        return session

    app.dependency_overrides[get_session] = get_session_override
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


def test_create_user(client: TestClient):
    response =  client.post("/user", json={"name": "test", "email": "invalid@example.com", "password": "Password123"})
    _json = response.json()
    # assert response.code == 201
    assert 'name' in _json
    assert _json['name'] == "test"
    assert 'email' in _json
    assert _json['email'] == "invalid@example.com"
    assert 'password' in _json

def test_token(client: TestClient):
    response = client.post("/token", data={"username":"test", "password": "Password123", "grant_type": "password"})
    _json = response.json()

    assert 'access_token' in _json
    assert 'token_type' in _json
    assert _json['token_type'] == "bearer"