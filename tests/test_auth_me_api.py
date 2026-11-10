
import uuid

import pytest
from httpx import ASGITransport, AsyncClient

from app.core.database import AsyncSessionFactory
from app.core.tokens import create_access_token
from app.main import app
from app.models import User
from app.modules.auth.service import register_user


@pytest.mark.asyncio
async def test_get_me_returns_current_user() -> None:
    email = f"me-{uuid.uuid4().hex}@example.com"
    password = "StrongPassword123!"
    user_id = None

    try:
        async with AsyncSessionFactory() as session:
            user = await register_user(session, email, password)
            user_id = user.id

        access_token = create_access_token(user_id)

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            response = await client.get(
                "/auth/me",
                headers={"Authorization": f"Bearer {access_token}"},
            )

        assert response.status_code == 200
        assert response.json()["id"] == str(user_id)
        assert response.json()["email"] == email
        assert response.json()["is_active"] is True
        assert response.json()["is_verified"] is False

    finally:
        if user_id is not None:
            async with AsyncSessionFactory() as session:
                user = await session.get(User, user_id)
                if user is not None:
                    await session.delete(user)
                await session.commit()


@pytest.mark.asyncio
async def test_get_me_rejects_missing_token() -> None:
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.get("/auth/me")

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_get_me_rejects_invalid_token() -> None:
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.get(
            "/auth/me",
            headers={"Authorization": "Bearer invalid-token"},
        )

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_get_me_rejects_inactive_user() -> None:
    email = f"me-inactive-{uuid.uuid4().hex}@example.com"
    password = "StrongPassword123!"
    user_id = None

    try:
        async with AsyncSessionFactory() as session:
            user = await register_user(session, email, password)
            user.is_active = False
            user_id = user.id
            await session.commit()

        access_token = create_access_token(user_id)

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            response = await client.get(
                "/auth/me",
                headers={"Authorization": f"Bearer {access_token}"},
            )

        assert response.status_code == 403
        assert response.json()["detail"] == "User account is inactive"

    finally:
        if user_id is not None:
            async with AsyncSessionFactory() as session:
                user = await session.get(User, user_id)
                if user is not None:
                    await session.delete(user)
                await session.commit()
