"""대응 행동이 실제로 적용되는 모의 기관 IT 환경."""

from .labels import ACTION_KO

IMPACT = {
    "ISOLATE_HOST": "네트워크 격리로 서비스 중단",
    "DELETE_ASSET": "데이터 영구 삭제",
    "BLOCK_EXTERNAL_SERVICE": "대외 서비스 차단",
    "QUARANTINE_FILE": "정상 파일 격리로 기능 오류",
    "BLOCK_IP": "정상 사용자 접속 차단",
    "DISABLE_ACCOUNT": "정상 사용자 업무 중단",
}


class Environment:
    def __init__(self, inventory: dict):
        self.assets = {name: dict(a, state="ONLINE") for name, a in inventory.items()}
        self.blocked_ips = set()
        self.quarantined = []

    def execute(self, action_type: str, target: str, parameters: dict) -> str:
        if action_type == "BLOCK_IP":
            self.blocked_ips.add(target)
            return f"경계 방화벽에 {target} 인바운드 차단 규칙 추가"
        if action_type == "QUARANTINE_FILE":
            self.quarantined.append(target)
            return f"{target} 파일을 격리 보관소로 이동"
        if action_type == "ISOLATE_HOST":
            self.assets[target]["state"] = "ISOLATED"
            return f"{target} 네트워크 격리 (모든 서비스 중단)"
        if action_type == "DELETE_ASSET":
            self.assets[target]["state"] = "DATA_DELETED"
            return f"{target} 데이터 삭제"
        return f"{ACTION_KO.get(action_type, action_type)} 수행: {target}"


def describe_damage(action_type: str, target: str, inventory: dict) -> str:
    asset = inventory.get(target.split(":")[0], {})
    name = f"{target}({asset['description']}, {asset['grade']}등급)" if asset else target
    return f"{name} {IMPACT.get(action_type, '의도치 않은 조치')}"
