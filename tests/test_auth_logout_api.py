import uuid

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.core.database import AsyncSessionFactory
from app.main import app
from app.models import RefreshToken, User
from app.modules.auth.service import register_user


@pytest.mark.asyncio
async def test_logout_revokes_refresh_token() -> None:
    email = f"logout-{uuid.uuid4().hex}@example.com"
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
            login_response = await client.post(
                "/auth/login",
                json={"email": email, "password": password},
            )

            assert login_response.status_code == 200

            refresh_token = login_response.json()["refresh_token"]

            logout_response = await client.post(
                "/auth/logout",
                json={"refresh_token": refresh_token},
            )

        assert logout_response.status_code == 204
        assert logout_response.content == b""

        async with AsyncSessionFactory() as session:
            result = await session.execute(
                select(RefreshToken).where(
                    RefreshToken.user_id == user_id,
                )
            )
            records = result.scalars().all()

            assert len(records) == 1
            assert records[0].revoked_at is not None

    finally:
        if user_id is not None:
            async with AsyncSessionFactory() as session:
                user = await session.get(User, user_id)
                if user is not None:
                    await session.delete(user)
                await session.commit()


@pytest.mark.asyncio
async def test_logout_accepts_unknown_token() -> None:
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/auth/logout",
            json={"refresh_token": "unknown-refresh-token"},
        )

    assert response.status_code == 204


@pytest.mark.asyncio
async def test_logout_is_idempotent() -> None:
    email = f"logout-repeat-{uuid.uuid4().hex}@example.com"
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
            login_response = await client.post(
                "/auth/login",
                json={"email": email, "password": password},
            )

            refresh_token = login_response.json()["refresh_token"]

            first_response = await client.post(
                "/auth/logout",
                json={"refresh_token": refresh_token},
            )

            second_response = await client.post(
                "/auth/logout",
                json={"refresh_token": refresh_token},
            )

        assert first_response.status_code == 204
        assert second_response.status_code == 204

    finally:
        if user_id is not None:
            async with AsyncSessionFactory() as session:
                user = await session.get(User, user_id)
                if user is not None:
                    await session.delete(user)
                await session.commit()