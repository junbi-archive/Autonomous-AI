"""사전 승인을 판단하는 승인자(운영자) 모델."""

from dataclasses import dataclass, field

from .labels import ACTION_KO, GRADE_KO, MODE_KO


@dataclass
class ApprovalRequest:
    log_id: str
    action_type: str
    target: str
    target_grade: str
    summary: str
    reasoning_steps: list
    evidence: list          # [{"evidence_id","source","content"}]
    confidence: float
    risk: dict
    warnings: list = field(default_factory=list)


@dataclass
class Decision:
    approved: bool
    approver: str
    comment: str
    review_seconds: int = 300


class CarefulOperator:
    """경고를 확인하고, 기관이 아는 정상 업무 맥락(변경관리 기록)과 대조하는 운영자."""

    approver_id = "soc-operator-park"

    def __init__(self, known_sessions=None):
        self.known_sessions = known_sessions or []

    def decide(self, req: ApprovalRequest) -> Decision:
        high = [w for w in req.warnings if w["severity"] == "HIGH"]
        if high:
            codes = ", ".join(sorted({w["code"] for w in high}))
            return Decision(False, self.approver_id,
                            f"보안 경고({codes}) 확인. 대응 근거가 신뢰할 수 없는 외부 입력에서 유래하므로 "
                            "승인 거부하고 인젝션 공격 건으로 에스컬레이션", 420)
        text = "\n".join(e["content"] for e in req.evidence)
        for s in self.known_sessions:
            if s["user"] in text and s["ip_prefix"] in text:
                return Decision(False, self.approver_id,
                                f"등록된 정상 작업과 일치: {s['note']}. 오탐으로 판단하여 거부", 600)
        return Decision(True, self.approver_id, "판단근거와 원본 증거 대조 결과 타당하여 승인", 300)

    def post_review(self, record: dict, truth: str) -> tuple:
        if truth == "TRUE_POSITIVE":
            return truth, "NONE", "원본 증거 재확인 결과 정탐. 조치 유지"
        return truth, "ROLLED_BACK", "사후 검토 결과 부적절한 조치로 판단, 원상 복구"


class NegligentOperator:
    """경고 내용을 읽지 않고 형식적으로 승인하는 운영자 (운영자 과실 시연용)."""

    approver_id = "soc-operator-choi"

    def decide(self, req: ApprovalRequest) -> Decision:
        return Decision(True, self.approver_id, "확인함", 20)

    def post_review(self, record: dict, truth: str) -> tuple:
        return "TRUE_POSITIVE", "NONE", "이상 없음"


class InteractiveOperator(CarefulOperator):
    """시연 현장에서 사람이 직접 승인·거부를 입력한다."""

    approver_id = "live-demo-operator"

    def decide(self, req: ApprovalRequest) -> Decision:
        print("\n" + "=" * 72)
        print(f"  [사전 승인 요청] {req.log_id}")
        print("=" * 72)
        print(f"  행동   : {ACTION_KO.get(req.action_type, req.action_type)}")
        print(f"  대상   : {req.target} ({GRADE_KO.get(req.target_grade, req.target_grade)})")
        print(f"  위험도 : {req.risk['tier']}단계 · {MODE_KO[req.risk['mode']]}")
        print(f"  신뢰도 : {req.confidence:.2f}")
        print(f"  판단근거: {req.summary}")
        for i, step in enumerate(req.reasoning_steps, 1):
            print(f"     {i}. {step}")
        for ev in req.evidence:
            print(f"  증거 {ev['evidence_id']} ({ev['source']})")
            for line in ev["content"].splitlines()[:6]:
                print(f"     | {line[:150]}")
        if req.warnings:
            print("  ⚠ 보안 경고")
            for w in req.warnings:
                print(f"     - [{w['severity']}] {w['code']}: {w['detail']}")
        while True:
            ans = input("  승인하시겠습니까? (y/n) > ").strip().lower()
            if ans in ("y", "n"):
                break
        comment = input("  의견 (Enter 생략) > ").strip() or ("승인" if ans == "y" else "거부")
        return Decision(ans == "y", self.approver_id, comment, 300)
