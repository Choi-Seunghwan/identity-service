from datetime import datetime
from typing import Optional
from pydantic import BaseModel


# 소셜 로그인 시작 (URL 반환)
class SocialLoginUrlDto(BaseModel):
    authorization_url: str


# Oauth callback 후 토큰 응답
class SocialLoginDto(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    is_new_user: bool  # 신규 가입 여부


# 소셜 계정 연결 요청
class ConnectSocialDto(BaseModel):
    provider: str  # google, kakao, naver
    code: str  # Oauth authorization code


# 소셜 계정 정보 응답
class SocialAccountDto(BaseModel):
    id: str
    provider: str
    email: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


# OAuth Provider에서 받은 사용자 정보
class OAuthUserInfo(BaseModel):
    provider_user_id: str
    email: Optional[str] = None
    name: Optional[str] = None
