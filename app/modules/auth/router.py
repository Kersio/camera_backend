from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.core.tokens import create_access_token
from app.models import User
from app.modules.auth.dependencies import get_current_user
from app.modules.auth.schemas import (
    RefreshRequest,
    TokenResponse,
    UserLogin,
    UserRegister,
    UserResponse,
)
from app.modules.auth.service import (
    DefaultRoleNotConfiguredError,
    EmailAlreadyRegisteredError,
    InvalidCredentialsError,
    authenticate_user,
    register_user,
)
from app.modules.auth.service import (
    InactiveUserError as AuthenticationInactiveUserError,
)
from app.modules.auth.token_service import (
    InactiveUserError as TokenInactiveUserError,
)
from app.modules.auth.token_service import (
    InvalidRefreshTokenError,
    create_refresh_token_record,
    revoke_refresh_token,
    rotate_refresh_token,
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


@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
)
async def login(
    user_data: UserLogin,
    session: Annotated[AsyncSession, Depends(get_db)],
) -> TokenResponse:
    """Проверяет учётные данные и выдаёт пару токенов."""

    try:
        user = await authenticate_user(
            session=session,
            email=str(user_data.email),
            password=user_data.password,
        )

    except InvalidCredentialsError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None

    except AuthenticationInactiveUserError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive",
        ) from None

    try:
        refresh_token = await create_refresh_token_record(
            session=session,
            user_id=user.id,
        )

        await session.commit()

    except Exception:
        await session.rollback()
        raise

    access_token = create_access_token(user.id)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.post(
    "/refresh",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
)
async def refresh(
    token_data: RefreshRequest,
    session: Annotated[AsyncSession, Depends(get_db)],
) -> TokenResponse:
    """Обновляет пару токенов с ротацией Refresh Token."""

    try:
        user_id, new_refresh_token = await rotate_refresh_token(
            session=session,
            raw_token=token_data.refresh_token,
        )

    except InvalidRefreshTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        ) from None

    except TokenInactiveUserError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive",
        ) from None

    access_token = create_access_token(user_id)

    return TokenResponse(
        access_token=access_token,
        refresh_token=new_refresh_token,
        token_type="bearer",
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def logout(
    token_data: RefreshRequest,
    session: Annotated[AsyncSession, Depends(get_db)],
) -> Response:
    """Завершает текущую сессию, отзывая Refresh Token."""

    try:
        await revoke_refresh_token(
            session=session,
            raw_token=token_data.refresh_token,
        )

        await session.commit()

    except Exception:
        await session.rollback()
        raise

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/me",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
)
async def get_me(
    current_user: Annotated[User, Depends(get_current_user)],
) -> UserResponse:
    """Возвращает данные текущего пользователя."""

    return UserResponse.model_validate(current_user)