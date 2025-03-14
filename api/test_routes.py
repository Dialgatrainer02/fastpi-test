import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine
from sqlmodel.pool import StaticPool

from . import get_session, app
from .utils import hash_password, verify_token
from .models import *


@pytest.fixture(name="session")
def session_fixture():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    SQLModel.metadata.create_all(engine)
    u = User(
        name = "tester",
        email = "invalid@example.com",
        password = hash_password("Password1")
    )

    with Session(engine) as session:
        session.add(u) # generate test user
        session.commit()
        session.refresh(u)
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
    response =  client.post("/user", json={"name": "test2", "email": "invalid@example.com", "password": "Password123"})
    _json = response.json()
    # assert response.code == 201
    assert 'name' in _json
    assert _json['name'] == "test2"
    assert 'email' in _json
    assert _json['email'] == "invalid@example.com"


def test_token(client: TestClient):
    response = client.post("/token", data={"username":"tester", "password": "Password1", "grant_type": "password"})
    _json = response.json()

    assert verify_token(_json['access_token']) == True # should propbaly test incorrect issuer token as well

    assert 'access_token' in _json
    assert 'token_type' in _json
    assert _json['token_type'] == "bearer"
    return _json['access_token']

def test_list_user(client: TestClient):
    user_token = test_token(client)
    response = client.get("/user",headers={"Authorization": f"Bearer {user_token}"})
    _json = response.json()

    assert _json[0].get('name') == "tester"
    assert _json[0].get('email') == "invalid@example.com"
    assert not _json[0].get('password')
    return _json[0].get('id')

def test_patch_user(client: TestClient):
    user_token = test_token(client)
    user_id = test_list_user(client)
    # print(user_id, user_token)
    response = client.patch(f"/user/{user_id}",headers={"Authorization": f"Bearer {user_token}"}, json={"name": "test2","password": "Password2","email": "example@example.com"})
    _json = response.json()

    unauthenticated_response = client.patch("/user",params={"id": user_id}, json={"name": "test2","password": "Password2","email": "example@example.com"})
    assert unauthenticated_response.status_code == 401 | 405
    assert 'name' in _json
    assert 'email' in _json
    assert _json['name'] == "test2"
    assert _json['email'] == "example@example.com"

def test_put_user(client: TestClient):
    user_token = test_token(client)
    user_id = test_list_user(client)
    # print(user_id, user_token)
    response = client.put(f"/user/{user_id}",headers={"Authorization": f"Bearer {user_token}"}, json={"name": "test2","password": "Password2","email": "example@example.com"})
    _json = response.json()

    partial_response = client.put(f"/user/{user_id}",headers={"Authorization": f"Bearer {user_token}"}, json={"name": "test2","password": "Password2"})
    assert partial_response.status_code == 422
    assert 'name' in _json
    assert 'email' in _json

    assert _json['name'] == "test2"
    assert _json['email'] == "example@example.com"


def test_delete_user(client: TestClient):
    user_token = test_token(client)
    user_id = test_list_user(client)
    response = client.delete(f"/user/{user_id}",headers={"Authorization": f"Bearer {user_token}"})
    assert response.status_code == 204