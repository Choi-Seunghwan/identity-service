from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, Field


# Base DTO
class UserBaseDto(BaseModel):
    email: EmailStr
    username: Optional[str] = None
    phone_number: Optional[str] = None


# 회원가입 요청 DTO
class CreateUserDto(UserBaseDto):
    password: str = Field(..., min_length=8, max_length=100)


# 사용자 응답 DTO
class UserDto(UserBaseDto):
    id: str
    is_active: bool
    is_verified: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# 사용자 업데이트 DTO
class UpdateUserDto(BaseModel):
    username: Optional[str] = None
    phone_number: Optional[str] = None


# 비밀번호 변경 DTO
class ChangePasswordDto(BaseModel):
    old_password: str
    new_password: str = Field(..., min_length=8, max_length=100)
