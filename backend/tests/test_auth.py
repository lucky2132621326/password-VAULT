import time

import pyotp
from sqlmodel import Session, select

from backend.models import User


ACCOUNT_PASSWORD = "Correct-Horse-Account-Password-2026"


def register(client, username="alice"):
    response = client.post("/api/auth/register", json={
        "username": username,
        "name": "Alice Menon",
        "accountPassword": ACCOUNT_PASSWORD,
    })
    assert response.status_code == 201, response.text
    return response.json()


def confirm(client, registration, offset=-1):
    totp = pyotp.TOTP(registration["totp"]["secret"])
    code = totp.at(time.time() + offset * 30)
    response = client.post("/api/auth/enroll/confirm", json={
        "challengeToken": registration["challengeToken"],
        "code": code,
    })
    assert response.status_code == 200, response.text
    return response.json()


def login_challenge(client, username="alice", password=ACCOUNT_PASSWORD):
    response = client.post("/api/auth/login", json={
        "username": username,
        "accountPassword": password,
    })
    return response


def test_health(client):
    assert client.get("/api/health").json() == {"ok": True}


def test_register_encrypts_totp_seed_and_confirms_mfa(client, app):
    registration = register(client)
    secret = registration["totp"]["secret"]
    assert registration["totp"]["period"] == 30
    assert registration["totp"]["uri"].startswith("otpauth://totp/")

    with Session(app.state.engine) as session:
        user = session.exec(select(User).where(User.username == "alice")).one()
        assert user.totp_confirmed is False
        assert secret not in user.totp_secret_encrypted
        assert ACCOUNT_PASSWORD not in user.account_password_hash

    result = confirm(client, registration)
    assert result["user"]["mfa"] is True
    assert len(result["recoveryCodes"]) == 8
    assert all(len(code.replace("-", "")) == 20 for code in result["recoveryCodes"])

    cookie = client.cookies.get("aegis_session")
    assert cookie
    assert client.get("/api/auth/me").json()["user"]["username"] == "alice"


def test_login_requires_password_then_fresh_totp(client):
    registration = register(client)
    confirm(client, registration, offset=-1)
    client.cookies.clear()

    wrong = login_challenge(client, password="Wrong-Account-Password")
    assert wrong.status_code == 401
    assert wrong.json()["detail"] == "Invalid credentials"

    first = login_challenge(client)
    assert first.status_code == 200
    challenge = first.json()["challengeToken"]
    code = pyotp.TOTP(registration["totp"]["secret"]).now()
    verified = client.post("/api/auth/totp", json={"challengeToken": challenge, "code": code})
    assert verified.status_code == 200, verified.text

    # Both the challenge and the 30-second TOTP value are one-use.
    replay = client.post("/api/auth/totp", json={"challengeToken": challenge, "code": code})
    assert replay.status_code == 401
    second_challenge = login_challenge(client).json()["challengeToken"]
    replay_code = client.post("/api/auth/totp", json={"challengeToken": second_challenge, "code": code})
    assert replay_code.status_code == 401


def test_recovery_code_is_a_single_use_second_factor(client):
    registration = register(client)
    enrollment = confirm(client, registration)
    recovery_code = enrollment["recoveryCodes"][0]
    client.cookies.clear()

    challenge = login_challenge(client).json()["challengeToken"]
    recovered = client.post("/api/auth/recovery", json={
        "challengeToken": challenge,
        "recoveryCode": recovery_code,
    })
    assert recovered.status_code == 200
    assert recovered.json()["recoveryCodeConsumed"] is True

    client.cookies.clear()
    second_challenge = login_challenge(client).json()["challengeToken"]
    replay = client.post("/api/auth/recovery", json={
        "challengeToken": second_challenge,
        "recoveryCode": recovery_code,
    })
    assert replay.status_code == 401


def test_enrollment_challenge_and_unknown_fields_are_rejected(client):
    registration = register(client)
    confirm(client, registration)
    code = pyotp.TOTP(registration["totp"]["secret"]).now()
    replay = client.post("/api/auth/enroll/confirm", json={
        "challengeToken": registration["challengeToken"], "code": code,
    })
    assert replay.status_code == 401

    extra = client.post("/api/auth/login", json={
        "username": "alice", "accountPassword": ACCOUNT_PASSWORD,
        "masterPassword": "must-never-cross-account-auth-boundary",
    })
    assert extra.status_code == 422


def test_logout_revokes_browser_cookie(client):
    registration = register(client)
    confirm(client, registration)
    assert client.get("/api/auth/me").status_code == 200
    assert client.post("/api/auth/logout").status_code == 200
    assert client.get("/api/auth/me").status_code == 401
