import base64

import pytest
from fastapi.testclient import TestClient

from backend.app import create_app
from backend.config import Settings


@pytest.fixture
def settings():
    return Settings(
        database_url="sqlite://",
        jwt_secret=b"j" * 32,
        mfa_encryption_key=b"m" * 32,
        cookie_secure=False,
        session_minutes=15,
        challenge_minutes=5,
    )


@pytest.fixture
def app(settings):
    return create_app(settings)


@pytest.fixture
def client(app):
    with TestClient(app) as value:
        yield value
