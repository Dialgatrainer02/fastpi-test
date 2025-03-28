import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine
from sqlmodel.pool import StaticPool

from . import get_session, app
from .utils import *
from .models import *


@pytest.fixture(name="session")
def session_fixture():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session

@pytest.fixture(name="user")
def user_fixture(session: Session) -> User:
    u = User(
        name = "tester",
        email = "invalid@example.com",
        password = hash_password("Password1")
    )
    session.add(u)
    session.commit()
    session.refresh(u)
    # print(u)
    return u


@pytest.fixture(name="client")
def client_fixture(session: Session):
    def get_session_override():
        return session

    app.dependency_overrides[get_session] = get_session_override
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


@pytest.fixture(name="token")
def token_fixture(session: Session, user: User) -> Token:
    token = create_token({ "sub": f"{str(user.id)}", "scopes": "user"}, timedelta(minutes=5))
    return Token(access_token=token, token_type="Bearer")


def test_create_user(client: TestClient):
    response =  client.post("/user", json={"name": "test2", "email": "invalid@example.com", "password": "Password123"})
    _json = response.json()
    # assert response.code == 201
    assert 'name' in _json
    assert _json['name'] == "test2"
    assert 'email' in _json
    assert _json['email'] == "invalid@example.com"


def test_token(client: TestClient, user: User, session: Session):
    response = client.post("/token", data={"username": f"{user.name}", "password": "Password1", "grant_type": "password"})
    scope_response = client.post("/token", data={"username": f"{user.name}", "password": "Password1", "scope": "user", "grant_type": "password"})
    _json = scope_response.json()
    

    assert verify_token(_json['access_token'],SecurityScopes(), session) == True # should propbaly test incorrect issuer token as well

    assert 'access_token' in _json
    assert 'token_type' in _json
    assert _json['token_type'] == "bearer"

def test_list_user(client: TestClient, token: Token):
    response = client.get("/user",headers={"Authorization": f"Bearer {token.access_token}"})
    _json = response.json()

    assert _json[0].get('name') == "tester"
    assert _json[0].get('email') == "invalid@example.com"
    assert not _json[0].get('password')


def test_patch_user(client: TestClient, user: User, token: Token):
    # print(user_id, user_token)
    response = client.patch(f"/user/{user.id}",headers={"Authorization": f"Bearer {token.access_token}"}, json={"name": "test2","password": "Password2","email": "example@example.com"})
    _json = response.json()

    unauthenticated_response = client.patch("/user",params={"id": user.id}, json={"name": "test2","password": "Password2","email": "example@example.com"})
    assert unauthenticated_response.status_code == 401 | 405
    assert 'name' in _json
    assert 'email' in _json
    assert _json['name'] == "test2"
    assert _json['email'] == "example@example.com"

def test_put_user(client: TestClient, user: User, token: Token):
    response = client.put(f"/user/{user.id}",headers={"Authorization": f"Bearer {token.access_token}"}, json={"name": "test2","password": "Password2","email": "example@example.com"})
    _json = response.json()

    partial_response = client.put(f"/user/{user.id}",headers={"Authorization": f"Bearer {token.access_token}"}, json={"name": "test2","password": "Password2"})
    assert partial_response.status_code == 422
    assert 'name' in _json
    assert 'email' in _json

    assert _json['name'] == "test2"
    assert _json['email'] == "example@example.com"


def test_delete_user(client: TestClient,user: User, token: Token):
    response = client.delete(f"/user/{user.id}",headers={"Authorization": f"Bearer {token.access_token}"})
    assert response.status_code == 204


def test_create_booking(client: TestClient, user: User, token: Token):
    response =  client.post(f"/booking/{user.id}",headers={"Authorization": f"Bearer {token.access_token}"} ,json={"location": "right here", "time": "right now"})
    _json = response.json()
    assert response.status_code == 200
    print(_json)
    assert 'location' in _json
    assert _json['location'] == "right here"
    assert 'time' in _json
    assert _json['time'] == "right now"
