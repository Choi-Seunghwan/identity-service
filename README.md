# Identity Service

사내 SSO를 위한 통합 인증 서비스 - FastAPI 기반

## 주요 기능

- **이메일 회원가입/로그인** - JWT 기반 인증
- **소셜 로그인** - Google, Kakao, Naver OAuth2
- **SSO (OAuth2/OIDC)** - 사내 서비스 통합 인증
  - OAuth2 Authorization Code Flow
  - OpenID Connect (ID Token, UserInfo)
  - Client 등록 및 관리

## 기술 스택

- **Framework**: FastAPI
- **Database**: PostgreSQL (async)
- **ORM**: SQLAlchemy 2.0
- **패키지 매니저**: uv

## 프로젝트 구조

```
app/
├── core/          # 핵심 기능 (DB, Security, Exceptions)
├── user/          # 회원 도메인
├── auth/          # 인증 도메인
├── social/        # 소셜 로그인 도메인
└── sso/           # SSO 도메인 (OAuth2/OIDC)
```

각 도메인은 DDD + Clean Architecture 패턴을 따릅니다:
- `model.py` - 엔티티
- `dto.py` - DTO
- `persistence.py` - Repository
- `service.py` - 비즈니스 로직
- `api.py` - 라우터

## 시작하기

### 1. 환경 설정

```bash
# .env 파일 생성 및 설정
cp .env.example .env
# DATABASE_URL, SECRET_KEY 등 설정
```

### 2. 의존성 설치

```bash
uv sync
```

### 3. 데이터베이스 마이그레이션

```bash
# 마이그레이션 실행
uv run alembic upgrade head
```

### 4. 서버 실행

```bash
uv run uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

API 문서: http://localhost:8000/docs

## 주요 API 엔드포인트

### 인증
- `POST /api/users` - 회원가입
- `POST /api/auth/login` - 로그인
- `POST /api/auth/refresh` - 토큰 갱신

### SSO (OAuth2/OIDC)
- `POST /api/oauth2/clients` - Client 등록
- `GET /api/oauth2/authorize` - Authorization 요청
- `POST /api/oauth2/token` - Token 교환
- `GET /api/oauth2/userinfo` - 사용자 정보
- `GET /api/oauth2/jwks` - 공개키
- `GET /.well-known/openid-configuration` - OIDC 메타데이터

## SSO 사용 방법

### 1. Client 등록

```bash
POST /api/oauth2/clients
{
  "name": "내부 관리 시스템",
  "redirect_uri": "http://localhost:3000/callback",
  "client_type": "confidential"
}
```

### 2. OAuth2 Authorization Code Flow

1. 사용자를 `/api/oauth2/authorize`로 리다이렉트
2. 로그인 후 Authorization Code 받음
3. Code를 `/api/oauth2/token`으로 교환하여 Access Token 획득
4. Access Token으로 `/api/oauth2/userinfo`에서 사용자 정보 조회

## 개발

자세한 개발 로그는 `DEVELOPMENT_LOG.md` 참고
