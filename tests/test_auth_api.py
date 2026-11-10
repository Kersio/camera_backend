
import uuid

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete

from app.core.database import AsyncSessionFactory
from app.core.tokens import decode_access_token
from app.main import app
from app.models import User
from app.modules.auth.service import register_user
from app.modules.auth.token_service import get_refresh_token_record


@pytest.mark.asyncio
async def test_login_successfully() -> None:
    email = f"api-login-{uuid.uuid4().hex}@example.com"
    password = "StrongPassword123!"

    user_id = None

    try:
        async with AsyncSessionFactory() as session:
            user = await register_user(session, email, password)
            user_id = user.id

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            response = await client.post(
                "/auth/login",
                json={
                    "email": email,
                    "password": password,
                },
            )

        assert response.status_code == 200

        data = response.json()

        assert data["access_token"]
        assert data["refresh_token"]
        assert data["token_type"] == "bearer"
        assert data["expires_in"] == 900

        # Проверяем, что Access Token содержит ID пользователя.
        access_user_id = decode_access_token(data["access_token"])
        assert access_user_id == user_id

        # Проверяем, что Refresh Token действительно сохранён в БД.
        async with AsyncSessionFactory() as session:
            record = await get_refresh_token_record(
                session,
                data["refresh_token"],
            )

            assert record is not None
            assert record.user_id == user_id
            assert record.revoked_at is None

    finally:
        if user_id is not None:
            async with AsyncSessionFactory() as session:
                await session.execute(
                    delete(User).where(User.id == user_id)
                )
                await session.commit()


@pytest.mark.asyncio
async def test_login_rejects_wrong_password() -> None:
    email = f"api-wrong-password-{uuid.uuid4().hex}@example.com"
    user_id = None

    try:
        async with AsyncSessionFactory() as session:
            user = await register_user(
                session,
                email,
                "StrongPassword123!",
            )
            user_id = user.id

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            response = await client.post(
                "/auth/login",
                json={
                    "email": email,
                    "password": "WrongPassword123!",
                },
            )

        assert response.status_code == 401
        assert response.json()["detail"] == "Incorrect email or password"

    finally:
        if user_id is not None:
            async with AsyncSessionFactory() as session:
                await session.execute(
                    delete(User).where(User.id == user_id)
                )
                await session.commit()


@pytest.mark.asyncio
async def test_login_rejects_unknown_email() -> None:
    email = f"unknown-{uuid.uuid4().hex}@example.com"

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/auth/login",
            json={
                "email": email,
                "password": "StrongPassword123!",
            },
        )

    assert response.status_code == 401
    assert response.json()["detail"] == "Incorrect email or password"


@pytest.mark.asyncio
async def test_login_rejects_inactive_user() -> None:
    email = f"api-inactive-{uuid.uuid4().hex}@example.com"
    password = "StrongPassword123!"

    user_id = None

    try:
        async with AsyncSessionFactory() as session:
            user = await register_user(session, email, password)
            user_id = user.id

            user.is_active = False
            await session.commit()

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            response = await client.post(
                "/auth/login",
                json={
                    "email": email,
                    "password": password,
                },
            )

        assert response.status_code == 403
        assert response.json()["detail"] == "User account is inactive"

    finally:
        if user_id is not None:
            async with AsyncSessionFactory() as session:
                await session.execute(
                    delete(User).where(User.id == user_id)
                )
                await session.commit()
