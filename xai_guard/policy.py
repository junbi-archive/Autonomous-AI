"""위험도 산정 정책 (고시안 제7·8조).

위험단계 -> 개입 방식
  1단계 LOW    : AUTO          자동 실행
  2단계 MEDIUM : POST_REVIEW   실행 후 검토 (SLA 내 사람이 사후 확인)
  3단계 HIGH   : PRE_APPROVAL  사전 승인 필수

단계 = max(행동 유형 기본 단계, N2SF 자산등급 단계), 고위험 행동(삭제·격리·대외서비스 차단)은
무조건 3단계, 신뢰도가 기준 미만이면 한 단계 상향, 고위험 보안경고(인젝션 등)가 있으면 3단계.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path

DATA_DIR = Path(__file__).parent / "data"

LEVELS = {1: "LOW", 2: "MEDIUM", 3: "HIGH"}
MODES = {1: "AUTO", 2: "POST_REVIEW", 3: "PRE_APPROVAL"}


@dataclass
class RiskAssessment:
    tier: int
    level: str
    mode: str
    factors: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"tier": self.tier, "level": self.level, "mode": self.mode, "factors": self.factors}


class Policy:
    def __init__(self, data: dict):
        self.version = data["version"]
        self.description = data.get("description", "")
        self.action_tier = data["action_base_tier"]
        self.grade_tier = data["asset_grade_tier"]
        self.high_risk = set(data["high_risk_actions"])
        self.low_confidence = data["low_confidence_escalation"]
        self.escalate_on_high_flags = data["escalate_on_high_flags"]
        self.post_review_sla_hours = data["post_review_sla_hours"]

    @classmethod
    def load(cls, path) -> "Policy":
        return cls(json.loads(Path(path).read_text(encoding="utf-8")))

    @classmethod
    def standard(cls) -> "Policy":
        return cls.load(DATA_DIR / "policy_standard.json")

    @classmethod
    def agency_lax(cls) -> "Policy":
        return cls.load(DATA_DIR / "policy_agency_lax.json")

    def assess(self, action_type: str, target_grade: str, confidence: float, flags: list) -> RiskAssessment:
        tier = self.action_tier.get(action_type, 2)
        factors = [f"행동 유형 {action_type} 기본 {tier}단계"]
        grade_tier = self.grade_tier.get(target_grade)
        if grade_tier and grade_tier > tier:
            tier = grade_tier
            factors.append(f"N2SF {target_grade}등급 자산 대상 → {grade_tier}단계")
        if action_type in self.high_risk:
            tier = 3
            factors.append("고위험 행동(삭제·격리·대외서비스 차단) 지정 → 3단계")
        if confidence < self.low_confidence and tier < 3:
            tier += 1
            factors.append(f"신뢰도 {confidence:.2f} < {self.low_confidence} → 1단계 상향")
        high_flags = [f["code"] for f in flags if f.get("severity") == "HIGH"]
        if high_flags and self.escalate_on_high_flags and tier < 3:
            tier = 3
            factors.append(f"고위험 보안경고({', '.join(high_flags)}) → 3단계")
        return RiskAssessment(tier, LEVELS[tier], MODES[tier], factors)


def load_inventory() -> dict:
    data = json.loads((DATA_DIR / "assets.json").read_text(encoding="utf-8"))
    return {a["name"]: a for a in data["assets"]}
