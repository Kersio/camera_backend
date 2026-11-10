import pytest
from pydantic import ValidationError

from app.modules.auth.schemas import UserRegister


def test_valid_registration_data() -> None:
    user = UserRegister(
        email="operator@example.com",
        password="StrongPassword123!",
    )

    assert user.email == "operator@example.com"
    assert user.password == "StrongPassword123!"


def test_invalid_email_is_rejected() -> None:
    with pytest.raises(ValidationError):
        UserRegister(
            email="not-an-email",
            password="StrongPassword123!",
        )


def test_short_password_is_rejected() -> None:
    with pytest.raises(ValidationError):
        UserRegister(
            email="operator@example.com",
            password="short",
        )


def test_role_cannot_be_provided_by_client() -> None:
    user = UserRegister(
        email="operator@example.com",
        password="StrongPassword123!",
        role="admin",
    )

    assert not hasattr(user, "role")
