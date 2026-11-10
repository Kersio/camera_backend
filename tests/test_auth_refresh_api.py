import uuid

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select

from app.core.database import AsyncSessionFactory
from app.main import app
from app.models import RefreshToken, User
from app.modules.auth.service import register_user


@pytest.mark.asyncio
async def test_refresh_successfully() -> None:
    email = f"refresh-{uuid.uuid4().hex}@example.com"
    password = "StrongPassword123!"
    user_id = None
    old_refresh_token = None

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
            old_refresh_token = login_response.json()["refresh_token"]

            refresh_response = await client.post(
                "/auth/refresh",
                json={"refresh_token": old_refresh_token},
            )

        assert refresh_response.status_code == 200

        data = refresh_response.json()

        assert data["access_token"]
        assert data["refresh_token"]
        assert data["refresh_token"] != old_refresh_token
        assert data["token_type"] == "bearer"
        assert data["expires_in"] == 900

        async with AsyncSessionFactory() as session:
            old_result = await session.execute(
                select(RefreshToken).where(
                    RefreshToken.token_hash.is_not(None),
                    RefreshToken.user_id == user_id,
                )
            )
            records = old_result.scalars().all()

            assert len(records) == 2

            revoked_records = [
                record for record in records
                if record.revoked_at is not None
            ]
            active_records = [
                record for record in records
                if record.revoked_at is None
            ]

            assert len(revoked_records) == 1
            assert len(active_records) == 1

    finally:
        if user_id is not None:
            async with AsyncSessionFactory() as session:
                await session.execute(
                    delete(User).where(User.id == user_id)
                )
                await session.commit()


@pytest.mark.asyncio
async def test_refresh_rejects_unknown_token() -> None:
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/auth/refresh",
            json={"refresh_token": "unknown-refresh-token"},
        )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or expired refresh token"


@pytest.mark.asyncio
async def test_refresh_rejects_reused_token() -> None:
    email = f"reuse-{uuid.uuid4().hex}@example.com"
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

            old_token = login_response.json()["refresh_token"]

            first_refresh = await client.post(
                "/auth/refresh",
                json={"refresh_token": old_token},
            )

            assert first_refresh.status_code == 200

            second_refresh = await client.post(
                "/auth/refresh",
                json={"refresh_token": old_token},
            )

        assert second_refresh.status_code == 401

        async with AsyncSessionFactory() as session:
            result = await session.execute(
                select(RefreshToken).where(
                    RefreshToken.user_id == user_id,
                )
            )
            records = result.scalars().all()

            assert len(records) == 2
            assert all(record.revoked_at is not None for record in records)

    finally:
        if user_id is not None:
            async with AsyncSessionFactory() as session:
                await session.execute(
                    delete(User).where(User.id == user_id)
                )
                await session.commit()


@pytest.mark.asyncio
async def test_refresh_rejects_inactive_user() -> None:
    email = f"inactive-refresh-{uuid.uuid4().hex}@example.com"
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

        async with AsyncSessionFactory() as session:
            user = await session.get(User, user_id)
            assert user is not None
            user.is_active = False
            await session.commit()

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            response = await client.post(
                "/auth/refresh",
                json={"refresh_token": refresh_token},
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