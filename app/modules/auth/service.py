from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password, verify_password
from app.models import Role, User
from app.models.associations import user_roles


class EmailAlreadyRegisteredError(Exception):
    """Пользователь с таким email уже существует."""


class DefaultRoleNotConfiguredError(Exception):
    """В базе данных отсутствует обязательная роль operator."""

class InvalidCredentialsError(Exception):
    """Неверный email или пароль."""


class InactiveUserError(Exception):
    """Учётная запись пользователя отключена."""


async def register_user(
    session: AsyncSession,
    email: str,
    password: str,
) -> User:
    normalized_email = email.strip().lower()

    # Проверяем, зарегистрирован ли уже такой email.
    result = await session.execute(
        select(User).where(User.email == normalized_email)
    )
    existing_user = result.scalar_one_or_none()

    if existing_user is not None:
        raise EmailAlreadyRegisteredError

    # Получаем стандартную роль для новых пользователей.
    result = await session.execute(
        select(Role).where(Role.name == "operator")
    )
    operator_role = result.scalar_one_or_none()

    if operator_role is None:
        raise DefaultRoleNotConfiguredError

    # Создаём пользователя с Argon2id-хешем пароля.
    user = User(
        email=normalized_email,
        hashed_password=hash_password(password),
        is_active=True,
        is_verified=False,
    )

    try:
        session.add(user)
        await session.flush()

        statement = insert(user_roles).values(
            user_id=user.id,
            role_id=operator_role.id,
        )

        await session.execute(statement)
        await session.commit()

    except IntegrityError:
        await session.rollback()

        result = await session.execute(
            select(User).where(User.email == normalized_email)
        )

        if result.scalar_one_or_none() is not None:
            raise EmailAlreadyRegisteredError from None

        raise

    return user


async def authenticate_user(
    session: AsyncSession,
    email: str,
    password: str,
) -> User:
    """Проверяет учётные данные и возвращает пользователя."""

    normalized_email = email.strip().lower()

    result = await session.execute(
        select(User).where(User.email == normalized_email)
    )
    user = result.scalar_one_or_none()

    if user is None:
        raise InvalidCredentialsError

    if not verify_password(password, user.hashed_password):
        raise InvalidCredentialsError

    if not user.is_active:
        raise InactiveUserError

    return user
