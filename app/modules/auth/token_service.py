
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.tokens import create_refresh_token, hash_refresh_token
from app.models import RefreshToken, User


class InvalidRefreshTokenError(Exception):
    """Refresh Token недействителен."""


class RefreshTokenReuseError(InvalidRefreshTokenError):
    """Обнаружено повторное использование Refresh Token."""


class InactiveUserError(Exception):
    """Пользователь неактивен."""


async def create_refresh_token_record(
    session: AsyncSession,
    user_id: uuid.UUID,
    family_id: uuid.UUID | None = None,
) -> str:
    """Создаёт запись Refresh Token и возвращает исходный токен."""

    raw_token = create_refresh_token()

    record = RefreshToken(
        user_id=user_id,
        family_id=family_id or uuid.uuid4(),
        token_hash=hash_refresh_token(raw_token),
        expires_at=datetime.now(UTC)
        + timedelta(days=settings.refresh_token_expire_days),
    )

    session.add(record)
    await session.flush()

    return raw_token


async def get_refresh_token_record(
    session: AsyncSession,
    raw_token: str,
) -> RefreshToken | None:
    """Находит запись Refresh Token по его хешу."""

    result = await session.execute(
        select(RefreshToken).where(
            RefreshToken.token_hash == hash_refresh_token(raw_token)
        )
    )

    return result.scalar_one_or_none()


async def revoke_refresh_token(
    session: AsyncSession,
    raw_token: str,
) -> bool:
    """Отзывает один Refresh Token."""

    record = await get_refresh_token_record(session, raw_token)

    if record is None or record.revoked_at is not None:
        return False

    record.revoked_at = datetime.now(UTC)
    await session.flush()

    return True


async def revoke_token_family(
    session: AsyncSession,
    family_id: uuid.UUID,
) -> None:
    """Отзывает все активные токены одной семьи."""

    await session.execute(
        update(RefreshToken)
        .where(
            RefreshToken.family_id == family_id,
            RefreshToken.revoked_at.is_(None),
        )
        .values(revoked_at=datetime.now(UTC))
    )


async def rotate_refresh_token(
    session: AsyncSession,
    raw_token: str,
) -> tuple[uuid.UUID, str]:
    """Атомарно заменяет старый Refresh Token новым."""

    reuse_detected = False
    result: tuple[uuid.UUID, str] | None = None

    # Если транзакция уже открыта, используем SAVEPOINT.
    # Иначе создаём собственную транзакцию.
    transaction = (
        session.begin_nested()
        if session.in_transaction()
        else session.begin()
    )

    async with transaction:
        token_result = await session.execute(
            select(RefreshToken)
            .where(
                RefreshToken.token_hash == hash_refresh_token(raw_token)
            )
            .with_for_update()
            .execution_options(populate_existing=True)
        )

        old_record = token_result.scalar_one_or_none()

        if old_record is None:
            raise InvalidRefreshTokenError("Invalid refresh token")

        if old_record.revoked_at is not None:
            await revoke_token_family(session, old_record.family_id)
            reuse_detected = True

        else:
            now = datetime.now(UTC)

            if old_record.expires_at <= now:
                raise InvalidRefreshTokenError("Refresh token expired")

            # Блокируем строку пользователя для сериализации
            # параллельных операций с его Refresh Token.
            user_result = await session.execute(
                select(User)
                .where(User.id == old_record.user_id)
                .with_for_update()
            )

            user = user_result.scalar_one_or_none()

            if user is None or not user.is_active:
                raise InactiveUserError("User is inactive")

            new_raw_token = create_refresh_token()

            new_record = RefreshToken(
                id=uuid.uuid4(),
                user_id=old_record.user_id,
                family_id=old_record.family_id,
                token_hash=hash_refresh_token(new_raw_token),
                expires_at=now
                + timedelta(days=settings.refresh_token_expire_days),
            )

            session.add(new_record)
            await session.flush()

            old_record.revoked_at = now
            old_record.replaced_by = new_record.id

            await session.flush()

            result = (old_record.user_id, new_raw_token)

    if reuse_detected:
        raise RefreshTokenReuseError("Refresh token reuse detected")

    if result is None:
        raise InvalidRefreshTokenError("Invalid refresh token")

    return result
