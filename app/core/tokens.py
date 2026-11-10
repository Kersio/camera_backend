
import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta

import jwt
from jwt.exceptions import InvalidTokenError

from app.core.config import settings


class InvalidAccessTokenError(Exception):
    """Access JWT недействителен."""


def create_access_token(user_id: uuid.UUID) -> str:
    """Создаёт подписанный Access JWT для пользователя."""

    now = datetime.now(UTC)

    payload = {
        "sub": str(user_id),
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + timedelta(
            minutes=settings.access_token_expire_minutes
        ),
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "type": "access",
    }

    return jwt.encode(
        payload,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )


def decode_access_token(token: str) -> uuid.UUID:
    """Проверяет Access JWT и возвращает UUID пользователя."""

    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
            options={
                "require": [
                    "sub",
                    "jti",
                    "iat",
                    "exp",
                    "iss",
                    "aud",
                    "type",
                ],
            },
        )

        if payload.get("type") != "access":
            raise InvalidAccessTokenError("Invalid token type")

        return uuid.UUID(payload["sub"])

    except (InvalidTokenError, ValueError, TypeError, KeyError) as exc:
        raise InvalidAccessTokenError("Invalid access token") from exc


def create_refresh_token() -> str:
    """Создаёт криптографически стойкий Refresh Token."""

    return secrets.token_urlsafe(64)


def hash_refresh_token(token: str) -> str:
    """Возвращает SHA-256 хеш Refresh Token."""

    return hashlib.sha256(token.encode("utf-8")).hexdigest()
