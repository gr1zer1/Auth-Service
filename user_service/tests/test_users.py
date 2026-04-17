from types import SimpleNamespace

import pytest
from fastapi import HTTPException, Response

from users.routes import get_user_by_email, link_telegram_account, login, register
from users.schemas import TelegramLinkSchema, UserSchema


class FakeResult:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value


class FakeSession:
    def __init__(self, results=None):
        self.results = list(results or [])
        self.added = []
        self.committed = False
        self.refreshed = []

    async def execute(self, stmt):
        if self.results:
            return FakeResult(self.results.pop(0))
        return FakeResult(None)

    def add(self, item):
        item.id = getattr(item, "id", None) or 1
        item.is_active = getattr(item, "is_active", True)
        item.is_service = getattr(item, "is_service", False)
        self.added.append(item)

    async def commit(self):
        self.committed = True

    async def refresh(self, item):
        self.refreshed.append(item)


@pytest.mark.asyncio
async def test_register_creates_new_user():
    session = FakeSession(results=[None, None])

    result = await register(
        UserSchema(email="user@example.com", password="secret123", telegram_id=123),
        session,
    )

    assert result.email == "user@example.com"
    assert result.telegram_id == 123
    assert session.committed is True
    assert len(session.added) == 1


@pytest.mark.asyncio
async def test_register_rejects_duplicate_email():
    existing_user = SimpleNamespace(email="user@example.com")
    session = FakeSession(results=[existing_user])

    with pytest.raises(HTTPException) as exc:
        await register(
            UserSchema(email="user@example.com", password="secret123"),
            session,
        )

    assert exc.value.status_code == 409
    assert exc.value.detail == "User with this email already exists"


@pytest.mark.asyncio
async def test_login_returns_token_payload():
    existing_user = SimpleNamespace(
        id=7,
        email="user@example.com",
        password="$2b$12$MBrZJQ4Q8cWlLkT3QpcqYu8uA6v7SKNVr7ZXJQunwQ7LwL2D2d8VW",
        is_service=False,
        is_active=True,
        telegram_id=None,
    )
    session = FakeSession(results=[existing_user])

    from core.utility import hash_password

    existing_user.password = hash_password("secret123")

    result = await login(
        Response(),
        SimpleNamespace(username="user@example.com", password="secret123"),
        session,
    )

    assert result["token_type"] == "bearer"
    assert result["user"].email == "user@example.com"
    assert result["access_token"]


@pytest.mark.asyncio
async def test_link_telegram_updates_user():
    current_user = SimpleNamespace(id=5, telegram_id=None)
    session = FakeSession(results=[None])

    result = await link_telegram_account(
        TelegramLinkSchema(telegram_id=999),
        session,
        current_user,
    )

    assert result.telegram_id == 999
    assert session.committed is True


@pytest.mark.asyncio
async def test_link_telegram_rejects_conflict():
    session = FakeSession(results=[SimpleNamespace(id=11, telegram_id=777)])
    current_user = SimpleNamespace(id=5, telegram_id=None)

    with pytest.raises(HTTPException) as exc:
        await link_telegram_account(
            TelegramLinkSchema(telegram_id=777),
            session,
            current_user,
        )

    assert exc.value.status_code == 409
    assert exc.value.detail == "This Telegram account is already linked to another user"


@pytest.mark.asyncio
async def test_get_user_by_email_returns_existing_user():
    existing_user = SimpleNamespace(
        id=3,
        email="lookup@example.com",
        is_active=True,
        is_service=False,
        telegram_id=None,
    )
    session = FakeSession(results=[existing_user])

    result = await get_user_by_email("lookup@example.com", session)

    assert result.email == "lookup@example.com"
