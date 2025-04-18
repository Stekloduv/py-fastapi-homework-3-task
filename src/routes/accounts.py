from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import BaseSecurityError
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


@router.post("/register/", status_code=status.HTTP_201_CREATED)
def register_user(request: UserRegistrationRequestSchema, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.email == request.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {request.email} already exists.",
        )

    hashed_password = hash_password(request.password)

    new_user = User(
        email=request.email,
        password=hashed_password,
        user_group=UserGroupEnum.USER,
    )

    try:
        db.add(new_user)
        db.commit()

        activation_token = create_activation_token(new_user.id)

        new_activation_token = UserActivationToken(
            user_id=new_user.id,
            token=activation_token,
            expiration=activation_token_expiration,
        )
        db.add(new_activation_token)
        db.commit()

        return {
            "id": new_user.id,
            "email": new_user.email
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )

@router.post("/activate/", status_code=status.HTTP_201_CREATED)
def activate_user(request: UserActivationRequestSchema, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == request.email).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    elif user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User is already active.")

    activation_token = db.execute(
        select(ActivationTokenModel)
        .where(ActivationTokenModel.token == data.token, ActivationTokenModel.user_id == user.id)
    )
    activation_token = activation_token.scalar_one_or_none()
    if not activation_token or (
        activation_token.expires_at.replace(tzinfo=timezone.utc) <= datetime.now(tz=timezone.utc)
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )
    user.is_active = True
    db.delete(activation_token)
    db.commit()

    JSONResponse(content={"message": "User account activated successfully."})


@router.post("/password-reset/request/", status_code=status.HTTP_201_CREATED)
def request_password_reset(request: PasswordResetRequestSchema, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == request.email).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

@router.post("/password-reset/request/")
async def request_password_reset(
    data: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> Response:
    user = await db.execute(select(UserModel).where(UserModel.email == data.email))
    user = user.scalar_one_or_none()
    if user and user.is_active:
        await db.execute(
            delete(PasswordResetTokenModel)
            .where(PasswordResetTokenModel.user_id == user.id)
        )
        token = PasswordResetTokenModel(user_id=cast(int, user.id), user=user)
        db.add(token)
        await db.commit()

    return JSONResponse(content={"message": "If you are registered, you will receive an email with instructions."})


@router.post("/reset-password/complete/")
async def complete_password_reset(
    data: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> Response:
    user = await db.execute(select(UserModel).where(UserModel.email == data.email))
    user = user.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token.")
    reset_token = await db.execute(
        select(PasswordResetTokenModel)
        .where(PasswordResetTokenModel.token == data.token, PasswordResetTokenModel.user_id == user.id)
    )
    reset_token = reset_token.scalar_one_or_none()
    if not reset_token or reset_token.expires_at.replace(tzinfo=timezone.utc) <= datetime.now(tz=timezone.utc):
        await db.execute(
            delete(PasswordResetTokenModel)
            .where(PasswordResetTokenModel.user_id == user.id)
        )
        await db.commit()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token.")

    try:
        user._hashed_password = hash_password(data.password)
        await db.execute(
            delete(PasswordResetTokenModel)
            .where(PasswordResetTokenModel.user_id == user.id)
        )
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )

    return JSONResponse(content={"message": "Password reset successfully."})

@router.post("/login/", response_model=UserLoginResponseSchema, status_code=status.HTTP_201_CREATED)
async def user_login(
    data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):
    user = await db.execute(select(UserModel).where(UserModel.email == data.email))
    user = user.scalar_one_or_none()
    if not user or (user and not verify_password(data.password, user._hashed_password)):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password.")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User account is not activated.")

    try:
        refresh_token = jwt_manager.create_refresh_token(data={"user_id": user.id})
        access_token = jwt_manager.create_access_token(data={"user_id": user.id})
        refresh_token_model = RefreshTokenModel.create(
            user_id=user.id, token=refresh_token, days_valid=settings.LOGIN_TIME_DAYS
        )
        db.add(refresh_token_model)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )

    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


@router.post("/refresh/")
async def refresh_token(
    data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
) -> Response:
    try:
        decoded_token = jwt_manager.decode_refresh_token(data.refresh_token)
    except BaseSecurityError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Token has expired."
        )

    refresh_token_model = await db.execute(
        select(RefreshTokenModel)
        .where(
            RefreshTokenModel.token == data.refresh_token,
            RefreshTokenModel.user_id == decoded_token["user_id"]
        )
    )
    refresh_token_model = refresh_token_model.scalar_one_or_none()
    if not refresh_token_model:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token not found."
        )
    user = await db.execute(select(UserModel).where(UserModel.id == decoded_token["user_id"]))
    if not user.scalar():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found."
        )

    new_access_token = jwt_manager.create_access_token(data={"user_id": decoded_token["user_id"]})
    return JSONResponse(content={"access_token": new_access_token})

