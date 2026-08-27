import base64

from sqlmodel import Session, select

from backend.models import VaultProfileRecord
from .test_auth import confirm, register


SYNC_SECRET = "AEGIS-SYNC-" + base64.urlsafe_b64encode(b"y" * 32).decode("ascii").rstrip("=")
SYNC_HEADERS = {"X-Aegis-Vault-Authorization": SYNC_SECRET}


def encoded(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def blob(seed: bytes = b"c") -> dict:
    return {
        "v": 2,
        "alg": "AES-256-GCM",
        "iv": encoded(seed * 12),
        "ct": encoded(seed * 32),
    }


def profile() -> dict:
    return {
        "version": 2,
        "kdf": {
            "name": "PBKDF2-HMAC-SHA256",
            "iterations": 600_000,
            "hash": "SHA-256",
        },
        "salt": encoded(b"s" * 16),
        "wrappedVaultKey": blob(b"w"),
        "recoveryWrappedVaultKey": blob(b"r"),
        "wrappedSyncSecret": blob(b"y"),
    }


def item(app="Gmail") -> dict:
    return {
        "app": app,
        "username": "alice@example.com",
        "url": "https://mail.example.com",
        "category": "Email",
        "password": blob(b"p"),
        "strength": "elite",
        "entropy": 112,
        "createdAt": "2026-08-27T10:00:00Z",
        "updatedAt": "2026-08-27T10:00:00Z",
        "favorite": False,
        "locked": False,
        "compromisedAt": None,
        "compromiseReason": None,
        "breachNotifiedAt": None,
    }


def authenticated(client, username="alice"):
    confirm(client, register(client, username=username))


def test_vault_requires_completed_mfa_session(client):
    assert client.get("/api/vault").status_code == 401
    assert client.put(
        "/api/vault/profile", json={"profile": profile(), "expectedRevision": 0}, headers=SYNC_HEADERS
    ).status_code == 401


def test_wrapped_profile_round_trip_and_optimistic_version(client, app):
    authenticated(client)
    created = client.put(
        "/api/vault/profile", json={"profile": profile(), "expectedRevision": 0}, headers=SYNC_HEADERS
    )
    assert created.status_code == 200, created.text
    assert created.json()["revision"] == 1

    with Session(app.state.engine) as session:
        stored = session.exec(select(VaultProfileRecord)).one()
        assert stored is not None
        assert SYNC_SECRET not in stored.profile_json
        assert SYNC_SECRET != stored.sync_secret_hash

    snapshot = client.get("/api/vault").json()
    assert snapshot["profile"]["profile"] == profile()
    assert snapshot["items"] == []

    stale = client.put(
        "/api/vault/profile", json={"profile": profile(), "expectedRevision": 0}, headers=SYNC_HEADERS
    )
    assert stale.status_code == 409

    leaked_recovery_key = profile() | {"recoveryKey": "AEGIS-must-never-be-stored"}
    rejected = client.put(
        "/api/vault/profile",
        json={"profile": leaked_recovery_key, "expectedRevision": 1},
        headers=SYNC_HEADERS,
    )
    assert rejected.status_code == 422


def test_ciphertext_items_are_owned_versioned_and_tombstoned(client):
    authenticated(client)
    assert client.put(
        "/api/vault/profile", json={"profile": profile(), "expectedRevision": 0}, headers=SYNC_HEADERS
    ).status_code == 200
    created = client.put(
        "/api/vault/items/item_Alice01",
        json={"item": item(), "expectedRevision": 0},
        headers=SYNC_HEADERS,
    )
    assert created.status_code == 200, created.text
    assert created.json()["revision"] == 1
    assert created.json()["item"]["password"] == blob(b"p")

    stale = client.put(
        "/api/vault/items/item_Alice01",
        json={"item": item("Stale overwrite"), "expectedRevision": 0},
        headers=SYNC_HEADERS,
    )
    assert stale.status_code == 409

    updated = client.put(
        "/api/vault/items/item_Alice01",
        json={"item": item("GitHub"), "expectedRevision": 1},
        headers=SYNC_HEADERS,
    )
    assert updated.status_code == 200
    assert updated.json()["revision"] == 2

    invalid_ciphertext = item()
    invalid_ciphertext["password"] = invalid_ciphertext["password"] | {"iv": "not-base64"}
    rejected = client.put(
        "/api/vault/items/item_Invalid1",
        json={"item": invalid_ciphertext, "expectedRevision": 0},
        headers=SYNC_HEADERS,
    )
    assert rejected.status_code == 422

    deleted = client.delete("/api/vault/items/item_Alice01?expectedRevision=2", headers=SYNC_HEADERS)
    assert deleted.status_code == 200
    assert deleted.json()["deleted"] is True
    assert deleted.json()["item"] is None

    snapshot = client.get("/api/vault").json()
    assert snapshot["items"][0]["revision"] == 3
    assert snapshot["items"][0]["deleted"] is True
    assert snapshot["items"][0]["item"] is None


def test_users_cannot_read_or_mutate_each_others_items(client):
    authenticated(client, "alice")
    assert client.put(
        "/api/vault/profile", json={"profile": profile(), "expectedRevision": 0}, headers=SYNC_HEADERS
    ).status_code == 200
    assert client.put(
        "/api/vault/items/shared_item_01",
        json={"item": item(), "expectedRevision": 0},
        headers=SYNC_HEADERS,
    ).status_code == 200
    client.post("/api/auth/logout")

    authenticated(client, "bob")
    assert client.get("/api/vault").json()["items"] == []
    assert client.put(
        "/api/vault/profile", json={"profile": profile(), "expectedRevision": 0}, headers=SYNC_HEADERS
    ).status_code == 200
    assert client.delete(
        "/api/vault/items/shared_item_01?expectedRevision=1", headers=SYNC_HEADERS
    ).status_code == 404


def test_account_session_without_vault_unlock_cannot_mutate_data(client):
    authenticated(client)
    created = client.put(
        "/api/vault/profile", json={"profile": profile(), "expectedRevision": 0}, headers=SYNC_HEADERS
    )
    assert created.status_code == 200

    assert client.put(
        "/api/vault/items/blocked_item_01",
        json={"item": item(), "expectedRevision": 0},
    ).status_code == 403
    assert client.put(
        "/api/vault/profile",
        json={"profile": profile(), "expectedRevision": 1},
    ).status_code == 403

    wrong = {"X-Aegis-Vault-Authorization": "AEGIS-SYNC-" + "A" * 43}
    assert client.put(
        "/api/vault/items/blocked_item_01",
        json={"item": item(), "expectedRevision": 0},
        headers=wrong,
    ).status_code == 403
