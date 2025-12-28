from app.core.redis import get_redis
from app.core.exceptions import BadRequestException
from typing import Optional, Dict, Any
import json

# State 만료 시간 (초) - 10분
STATE_EXPIRE_SECONDS = 600

"""OAuth State 관리 모듈. CSRF 공격 방지를 위한 state 검증"""


async def save_oauth_state(
    state: str, provider: str, data: Optional[Dict[str, Any]] = None
) -> None:
    """
    OAuth state를 Redis에 저장

    state: 생성된 state 값
    provider: OAuth provider (google, kakao, naver)
    data: 추가 데이터 (예: redirect URL)
    """
    redis = await get_redis()
    key = f"oauth_state:{provider}:{state}"

    # 데이터가 있으면 JSON으로 저장, 없으면 "1" 저장
    value = json.dumps(data) if data else "1"
    await redis.setex(key, STATE_EXPIRE_SECONDS, value)


async def verify_oauth_state(state: str, provider: str) -> Optional[Dict[str, Any]]:
    """
    OAuth state를 검증하고 삭제 (일회용)

    Returns:
        저장된 데이터 (Dict) 또는 None
    """
    redis = await get_redis()
    key = f"oauth_state:{provider}:{state}"

    # State 값 가져오기
    value = await redis.get(key)

    if not value:
        raise BadRequestException(
            detail="Invalid or expired state. This may be a CSRF attack attempt."
        )

    # State 삭제 (일회용)
    await redis.delete(key)

    # JSON 파싱 시도
    try:
        data = json.loads(value)
        return data if isinstance(data, dict) else None
    except (json.JSONDecodeError, TypeError):
        # "1" 같은 단순 값이면 None 반환
        return None
