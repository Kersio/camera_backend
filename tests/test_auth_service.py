import uuid

import pytest
from sqlalchemy import delete, select

from app.core.database import AsyncSessionFactory
from app.core.security import verify_password
from app.models import Role, User
from app.models.associations import user_roles
from app.modules.auth.service import (
    EmailAlreadyRegisteredError,
    register_user,
)


@pytest.mark.asyncio
async def test_register_user_creates_user_with_operator_role() -> None:
    email = f"test-{uuid.uuid4().hex}@example.com"
    password = "StrongPassword123!"

    async with AsyncSessionFactory() as session:
        try:
            user = await register_user(session, email, password)

            assert user.email == email
            assert user.is_active is True
            assert user.is_verified is False

            # Проверяем, что сохранился хеш, а не исходный пароль.
            assert user.hashed_password != password
            assert verify_password(password, user.hashed_password)

            # Проверяем назначенную роль.
            result = await session.execute(
                select(Role.name)
                .join(
                    user_roles,
                    Role.id == user_roles.c.role_id,
                )
                .where(user_roles.c.user_id == user.id)
            )

            assert result.scalars().all() == ["operator"]

        finally:
            # Удаляем тестового пользователя и его связи.
            await session.execute(
                delete(User).where(User.email == email)
            )
            await session.commit()


@pytest.mark.asyncio
async def test_register_user_normalizes_email() -> None:
    email = f"TEST-{uuid.uuid4().hex}@EXAMPLE.COM"
    normalized_email = email.lower()

    async with AsyncSessionFactory() as session:
        try:
            user = await register_user(
                session,
                email,
                "StrongPassword123!",
            )

            assert user.email == normalized_email

        finally:
            await session.execute(
                delete(User).where(User.email == normalized_email)
            )
            await session.commit()


@pytest.mark.asyncio
async def test_register_user_rejects_duplicate_email() -> None:
    email = f"duplicate-{uuid.uuid4().hex}@example.com"

    async with AsyncSessionFactory() as session:
        try:
            await register_user(
                session,
                email,
                "StrongPassword123!",
            )

            with pytest.raises(EmailAlreadyRegisteredError):
                await register_user(
                    session,
                    email,
                    "AnotherPassword123!",
                )

        finally:
            await session.execute(
                delete(User).where(User.email == email)
            )
            await session.commit()