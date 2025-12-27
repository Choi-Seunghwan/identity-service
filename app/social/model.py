import enum
import uuid
from sqlalchemy import String, DateTime, ForeignKey, Enum as SQLEnum, UniqueConstraint
from sqlalchemy.orm import relationship, Mapped, mapped_column
from datetime import datetime, UTC
from app.core.database import Base
from app.user.model import User


class SocialProvider(str, enum.Enum):
    GOOGLE = "google"
    KAKAO = "kakao"
    NAVER = "naver"


class SocialAccount(Base):
    __tablename__ = "social_accounts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    provider: Mapped[SocialProvider] = mapped_column(SQLEnum(SocialProvider), nullable=False)
    provider_user_id: Mapped[str] = mapped_column(
        String(255), nullable=False
    )  # 소셜 제공자의 사용자 ID
    email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )

    user: Mapped["User"] = relationship(back_populates="social_accounts")

    # 같은 provider + provider_user_id는 한 번만
    __table_args__ = (UniqueConstraint("provider", "provider_user_id", name="uq_provider_user"),)
