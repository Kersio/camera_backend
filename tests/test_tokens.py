
import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest

from app.core.config import settings
from app.core.tokens import (
    InvalidAccessTokenError,
    create_access_token,
    create_refresh_token,
    decode_access_token,
    hash_refresh_token,
)


def test_create_access_token_contains_required_claims() -> None:
    user_id = uuid.uuid4()

    token = create_access_token(user_id)

    payload = jwt.decode(
        token,
        settings.jwt_secret_key,
        algorithms=[settings.jwt_algorithm],
        issuer=settings.jwt_issuer,
        audience=settings.jwt_audience,
    )

    assert payload["sub"] == str(user_id)
    assert payload["jti"]
    assert payload["iat"]
    assert payload["exp"]
    assert payload["iss"] == settings.jwt_issuer
    assert payload["aud"] == settings.jwt_audience
    assert payload["type"] == "access"


def test_create_access_token_generates_unique_jti() -> None:
    user_id = uuid.uuid4()

    first_token = create_access_token(user_id)
    second_token = create_access_token(user_id)

    first_payload = jwt.decode(
        first_token,
        settings.jwt_secret_key,
        algorithms=[settings.jwt_algorithm],
        issuer=settings.jwt_issuer,
        audience=settings.jwt_audience,
    )

    second_payload = jwt.decode(
        second_token,
        settings.jwt_secret_key,
        algorithms=[settings.jwt_algorithm],
        issuer=settings.jwt_issuer,
        audience=settings.jwt_audience,
    )

    assert first_payload["jti"] != second_payload["jti"]


def test_create_refresh_token_generates_unique_values() -> None:
    first_token = create_refresh_token()
    second_token = create_refresh_token()

    assert first_token != second_token
    assert len(first_token) >= 64


def test_hash_refresh_token_is_deterministic() -> None:
    token = create_refresh_token()

    first_hash = hash_refresh_token(token)
    second_hash = hash_refresh_token(token)

    assert first_hash == second_hash
    assert first_hash != token
    assert len(first_hash) == 64


def test_decode_access_token_returns_user_id() -> None:
    user_id = uuid.uuid4()

    token = create_access_token(user_id)

    assert decode_access_token(token) == user_id


def test_decode_access_token_rejects_invalid_signature() -> None:
    user_id = uuid.uuid4()

    tampered_token = jwt.encode(
        {
            "sub": str(user_id),
            "type": "access",
        },
        "wrong-secret",
        algorithm=settings.jwt_algorithm,
    )

    with pytest.raises(InvalidAccessTokenError):
        decode_access_token(tampered_token)


def test_decode_access_token_rejects_refresh_type() -> None:
    user_id = uuid.uuid4()
    now = datetime.now(UTC)

    payload = {
        "sub": str(user_id),
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + timedelta(minutes=5),
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "type": "refresh",
    }

    token = jwt.encode(
        payload,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )

    with pytest.raises(InvalidAccessTokenError):
        decode_access_token(token)
