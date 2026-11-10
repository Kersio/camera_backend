from app.core.security import hash_password, verify_password


def test_hash_password_returns_argon2_hash() -> None:
    password = "StrongPassword123!"

    hashed_password = hash_password(password)

    assert hashed_password != password
    assert hashed_password.startswith("$argon2id$")


def test_verify_password_accepts_correct_password() -> None:
    password = "StrongPassword123!"
    hashed_password = hash_password(password)

    assert verify_password(password, hashed_password) is True


def test_verify_password_rejects_incorrect_password() -> None:
    hashed_password = hash_password("StrongPassword123!")

    assert verify_password("WrongPassword123!", hashed_password) is False