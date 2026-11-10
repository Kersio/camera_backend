
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import delete

from app.core.database import AsyncSessionFactory
from app.core.tokens import hash_refresh_token
from app.models import User
from app.modules.auth.service import register_user
from app.modules.auth.token_service import (
    InactiveUserError,
    InvalidRefreshTokenError,
    RefreshTokenReuseError,
    create_refresh_token_record,
    get_refresh_token_record,
    revoke_refresh_token,
    revoke_token_family,
    rotate_refresh_token,
)


@pytest.mark.asyncio
async def test_create_refresh_token_record() -> None:
    email = f"token-{uuid.uuid4().hex}@example.com"

    async with AsyncSessionFactory() as session:
        user = None

        try:
            user = await register_user(
                session,
                email,
                "StrongPassword123!",
            )

            raw_token = await create_refresh_token_record(
                session,
                user.id,
            )

            record = await get_refresh_token_record(
                session,
                raw_token,
            )

            assert record is not None
            assert record.user_id == user.id
            assert record.token_hash == hash_refresh_token(raw_token)
            assert record.token_hash != raw_token
            assert record.revoked_at is None
            assert record.family_id is not None
            assert record.expires_at > datetime.now(UTC)

        finally:
            if user is not None:
                await session.execute(
                    delete(User).where(User.id == user.id)
                )
                await session.commit()


@pytest.mark.asyncio
async def test_get_refresh_token_record_returns_none_for_unknown_token() -> None:
    async with AsyncSessionFactory() as session:
        record = await get_refresh_token_record(
            session,
            "unknown-token",
        )

        assert record is None


@pytest.mark.asyncio
async def test_revoke_refresh_token() -> None:
    email = f"revoke-{uuid.uuid4().hex}@example.com"

    async with AsyncSessionFactory() as session:
        user = None
        user_id = None

        try:
            user = await register_user(
                session,
                email,
                "StrongPassword123!",
            )
            user_id = user.id

            raw_token = await create_refresh_token_record(
                session,
                user_id,
            )

            record = await get_refresh_token_record(
                session,
                raw_token,
            )

            assert record is not None
            assert record.revoked_at is None

            # Фиксируем создание пользователя и токена.
            await session.commit()

            # Вызываем именно функцию отзыва токена.
            revoked = await revoke_refresh_token(
                session,
                raw_token,
            )

            assert revoked is True

            await session.commit()
            await session.refresh(record)

            assert record.revoked_at is not None

            # Повторный отзыв уже отозванного токена
            # не должен считаться успешным.
            second_revoke = await revoke_refresh_token(
                session,
                raw_token,
            )

            assert second_revoke is False

        finally:
            if user_id is not None:
                await session.execute(
                    delete(User).where(User.id == user_id)
                )
                await session.commit()

@pytest.mark.asyncio
async def test_revoke_token_family() -> None:
    email = f"family-{uuid.uuid4().hex}@example.com"

    async with AsyncSessionFactory() as session:
        user = None

        try:
            user = await register_user(
                session,
                email,
                "StrongPassword123!",
            )
            family_id = uuid.uuid4()

            first_token = await create_refresh_token_record(
                session,
                user.id,
                family_id,
            )

            second_token = await create_refresh_token_record(
                session,
                user.id,
                family_id,
            )

            other_family_token = await create_refresh_token_record(
                session,
                user.id,
            )

            await revoke_token_family(session, family_id)
            await session.commit()

            first_record = await get_refresh_token_record(
                session,
                first_token,
            )
            second_record = await get_refresh_token_record(
                session,
                second_token,
            )
            other_record = await get_refresh_token_record(
                session,
                other_family_token,
            )

            assert first_record is not None
            assert second_record is not None
            assert other_record is not None

            assert first_record.revoked_at is not None
            assert second_record.revoked_at is not None
            assert other_record.revoked_at is None

        finally:
            if user is not None:
                await session.execute(
                    delete(User).where(User.id == user.id)
                )
                await session.commit()


@pytest.mark.asyncio
async def test_rotate_refresh_token_successfully() -> None:
    email = f"rotate-{uuid.uuid4().hex}@example.com"

    async with AsyncSessionFactory() as session:
        user = None

        try:
            user = await register_user(
                session,
                email,
                "StrongPassword123!",
            )

            old_raw_token = await create_refresh_token_record(
                session,
                user.id,
            )

            old_record = await get_refresh_token_record(
                session,
                old_raw_token,
            )

            assert old_record is not None
            old_family_id = old_record.family_id

            user_id, new_raw_token = await rotate_refresh_token(
                session,
                old_raw_token,
            )

            assert user_id == user.id
            assert new_raw_token != old_raw_token

            old_record = await get_refresh_token_record(
                session,
                old_raw_token,
            )
            new_record = await get_refresh_token_record(
                session,
                new_raw_token,
            )

            assert old_record is not None
            assert new_record is not None

            assert old_record.revoked_at is not None
            assert old_record.replaced_by == new_record.id

            assert new_record.revoked_at is None
            assert new_record.family_id == old_family_id

        finally:
            if user is not None:
                await session.execute(
                    delete(User).where(User.id == user.id)
                )
                await session.commit()


@pytest.mark.asyncio
async def test_reuse_of_old_token_revokes_entire_family() -> None:
    email = f"reuse-{uuid.uuid4().hex}@example.com"

    async with AsyncSessionFactory() as session:
        user = None

        try:
            user = await register_user(
                session,
                email,
                "StrongPassword123!",
            )

            old_raw_token = await create_refresh_token_record(
                session,
                user.id,
            )

            _, new_raw_token = await rotate_refresh_token(
                session,
                old_raw_token,
            )

            with pytest.raises(RefreshTokenReuseError):
                await rotate_refresh_token(
                    session,
                    old_raw_token,
                )

            old_record = await get_refresh_token_record(
                session,
                old_raw_token,
            )
            new_record = await get_refresh_token_record(
                session,
                new_raw_token,
            )

            assert old_record is not None
            assert new_record is not None

            assert old_record.revoked_at is not None
            assert new_record.revoked_at is not None

        finally:
            if user is not None:
                await session.execute(
                    delete(User).where(User.id == user.id)
                )
                await session.commit()


@pytest.mark.asyncio
async def test_rotate_refresh_token_rejects_expired_token() -> None:
    email = f"expired-{uuid.uuid4().hex}@example.com"

    async with AsyncSessionFactory() as session:
        user = None

        try:
            user = await register_user(
                session,
                email,
                "StrongPassword123!",
            )
            user_id = user.id
            raw_token = await create_refresh_token_record(
                session,
                user.id,
            )

            record = await get_refresh_token_record(
                session,
                raw_token,
            )

            assert record is not None

            record.expires_at = datetime.now(UTC) - timedelta(days=1)
            await session.commit()

            with pytest.raises(InvalidRefreshTokenError):
                await rotate_refresh_token(
                    session,
                    raw_token,
                )

        finally:
          if user is not None:
              await session.execute(
                  delete(User).where(User.id == user_id)
              )
              await session.commit()


@pytest.mark.asyncio
async def test_rotate_refresh_token_rejects_inactive_user() -> None:
    email = f"inactive-{uuid.uuid4().hex}@example.com"

    async with AsyncSessionFactory() as session:
        user = None

        try:
            user = await register_user(
                session,
                email,
                "StrongPassword123!",
            )
            user_id = user.id

            raw_token = await create_refresh_token_record(
                session,
                user.id,
            )

            user.is_active = False
            await session.commit()

            with pytest.raises(InactiveUserError):
                await rotate_refresh_token(
                    session,
                    raw_token,
                )

        finally:
            if user is not None:
              await session.execute(
                  delete(User).where(User.id == user_id)
              )
              await session.commit()