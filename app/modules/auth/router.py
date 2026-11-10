from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.modules.auth.schemas import UserRegister, UserResponse
from app.modules.auth.service import (
    DefaultRoleNotConfiguredError,
    EmailAlreadyRegisteredError,
    register_user,
)

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
async def register(
    user_data: UserRegister,
    session: Annotated[AsyncSession, Depends(get_db)],
) -> UserResponse:
    """Регистрирует нового пользователя."""

    if not settings.allow_public_registration:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Public registration is disabled",
        )

    try:
        user = await register_user(
            session=session,
            email=str(user_data.email),
            password=user_data.password,
        )

    except EmailAlreadyRegisteredError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with this email already exists",
        ) from None

    except DefaultRoleNotConfiguredError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Default user role is not configured",
        ) from None

    return UserResponse.model_validate(user)