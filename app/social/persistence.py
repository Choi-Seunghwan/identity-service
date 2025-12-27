from abc import ABC, abstractmethod
from typing import Optional

from sqlalchemy import select

from app.social.model import SocialAccount, SocialProvider
from sqlalchemy.ext.asyncio import AsyncSession


class SocialAccountRepository(ABC):

    @abstractmethod
    async def create(self, social_account: SocialAccount) -> SocialAccount: ...

    @abstractmethod
    async def find_by_provider_and_user_id(
        self, provider: SocialProvider, provider_user_id: str
    ) -> Optional[SocialAccount]: ...

    @abstractmethod
    async def find_by_user_id(self, user_id: str) -> list[SocialAccount]: ...

    @abstractmethod
    async def delete(self, social_account: SocialAccount) -> None: ...

    @abstractmethod
    async def exists_by_provider_and_user_id(
        self, provider: SocialProvider, provider_user_id: str
    ) -> bool: ...


class SocialAccountRepositoryImpl(SocialAccountRepository):
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create(self, social_account: SocialAccount) -> SocialAccount:
        """소셜 계정 생성"""
        self.db.add(social_account)
        await self.db.flush()
        await self.db.refresh(social_account)
        return social_account

    async def find_by_provider_and_user_id(
        self, provider: SocialProvider, provider_user_id: str
    ) -> Optional[SocialAccount]:
        """제공자 + 제공자 id로 조회"""
        result = await self.db.execute(
            select(SocialAccount)
            .where(SocialAccount.provider == provider)
            .where(SocialAccount.provider_user_id == provider_user_id)
        )
        return result.scalar_one_or_none()

    async def find_by_user_id(self, user_id: str) -> list[SocialAccount]:
        """유저의 모든 소셜 계정 조회"""
        result = await self.db.execute(
            select(SocialAccount).where(SocialAccount.user_id == user_id)
        )
        return list(result.scalars().all())

    async def delete(self, social_account: SocialAccount) -> None:
        """소셜 계정 삭제"""
        await self.db.delete(social_account)
        await self.db.flush()

    async def exists_by_provider_and_user_id(
        self, provider: SocialProvider, provider_user_id: str
    ) -> bool:
        """소셜 계정 존재 여부 확인"""
        result = await self.db.execute(
            select(SocialAccount.id)
            .where(SocialAccount.provider == provider)
            .where(SocialAccount.provider_user_id == provider_user_id)
        )
        return result.scalar_one_or_none() is not None
