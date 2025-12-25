from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db
from app.user.persistence import UserRepository, UserRepositoryImpl
from app.user.service import UserService


def get_user_repository(db: AsyncSession = Depends(get_db)) -> UserRepository:
    """UserRepository 의존성 주입"""
    return UserRepositoryImpl(db)


def get_user_service(user_repository: UserRepository = Depends(get_user_repository)) -> UserService:
    """UserService 의존성 주입"""
    return UserService(user_repository)
