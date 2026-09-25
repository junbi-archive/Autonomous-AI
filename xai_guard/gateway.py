"""위험도별 인간개입 게이트웨이 (고시안 제7~10조).

에이전트가 제안한 모든 행동은 이 게이트웨이를 거쳐야 실행된다.
  1) 참조한 원본 증거를 저장하고 해시로 고정
  2) 보안 경고(인젝션·출처 불일치·저신뢰) 탐지
  3) 정책에 따라 위험단계 산정 → 자동 실행 / 실행 후 검토 / 사전 승인
  4) 결과를 설명가능성 로그(XAL)로 해시체인 원장에 기록
"""

from dataclasses import dataclass
from datetime import timedelta

from . import detectors
from .approvers import ApprovalRequest
from .schema import SCHEMA_VERSION


@dataclass
class VendorProfile:
    """제품(개발사)이 표준 기능을 제대로 구현했는지를 나타내는 시연용 설정."""
    name: str = "표준 준수 제품"
    detect_warnings: bool = True     # 제10조 경고 탐지
    present_warnings: bool = True    # 제10조 승인자에게 경고 제시
    log_reasoning: bool = True       # 제4조 판단 과정 기록

    @classmethod
    def faulty(cls) -> "VendorProfile":
        return cls("탐지·기록 기능 미흡 제품", False, False, False)


class HumanOversightGateway:
    def __init__(self, *, policy, ledger, evidence_store, approver, environment, clock,
                 agency_id, system_info, vendor=None):
        self.policy = policy
        self.ledger = ledger
        self.evidence = evidence_store
        self.approver = approver
        self.env = environment
        self.clock = clock
        self.agency_id = agency_id
        self.system_info = system_info
        self.vendor = vendor or VendorProfile()
        self._counter = 0

    def submit(self, incident_id: str, proposal) -> dict:
        self._counter += 1
        log_id = f"{incident_id}-A{self._counter:02d}"
        decided_at = self.clock.iso()

        refs, contents = [], []
        for item in proposal.evidence:
            ref = self.evidence.put(item.source, item.content, decided_at)
            refs.append(ref)
            contents.append((ref["evidence_id"], item.content))

        flags = []
        if self.vendor.detect_warnings:
            flags = detectors.detect_warnings(contents, proposal.target, proposal.confidence)

        risk = self.policy.assess(proposal.action_type, proposal.target_grade, proposal.confidence, flags)
        approval = {"mode": risk.mode}

        if risk.mode == "AUTO":
            approval["status"] = "AUTO_EXECUTED"
            execute = True
        elif risk.mode == "POST_REVIEW":
            due = self.clock.now() + timedelta(hours=self.policy.post_review_sla_hours)
            approval.update(status="PENDING_REVIEW", review_due=due.isoformat())
            execute = True
        else:
            warnings = flags if self.vendor.present_warnings else []
            request = ApprovalRequest(
                log_id, proposal.action_type, proposal.target, proposal.target_grade,
                proposal.summary, proposal.reasoning_steps,
                [{"evidence_id": eid, "source": r["source"], "content": c}
                 for (eid, c), r in zip(contents, refs)],
                proposal.confidence, risk.to_dict(), warnings)
            approval["requested_at"] = self.clock.iso()
            decision = self.approver.decide(request)
            self.clock.advance(decision.review_seconds)
            approval.update(
                status="APPROVED" if decision.approved else "REJECTED",
                approver=decision.approver,
                decided_at=self.clock.iso(),
                comment=decision.comment,
                presented_warnings=[w["code"] for w in warnings],
            )
            execute = decision.approved

        if execute:
            effect = self.env.execute(proposal.action_type, proposal.target, proposal.parameters)
            execution = {"status": "EXECUTED", "executed_at": self.clock.iso(), "effect": effect}
        else:
            execution = {"status": "NOT_EXECUTED", "reason": "사전 승인 거부"}

        record = {
            "schema_version": SCHEMA_VERSION,
            "record_type": "ACTION",
            "log_id": log_id,
            "timestamp": decided_at,
            "incident_id": incident_id,
            "agency_id": self.agency_id,
            "system": self.system_info,
            "action": {"type": proposal.action_type, "target": proposal.target,
                       "target_grade": proposal.target_grade, "parameters": proposal.parameters},
            "rationale": {"summary": proposal.summary,
                          "reasoning_steps": proposal.reasoning_steps if self.vendor.log_reasoning else []},
            "evidence": refs,
            "confidence": proposal.confidence,
            "risk": risk.to_dict(),
            "approval": approval,
            "execution": execution,
            "security_flags": flags,
            "policy_version": self.policy.version,
        }
        self.clock.advance(5)
        return self.ledger.append(record)

    def _review(self, kind, record, reviewer, verdict, remediation, comment) -> dict:
        self._counter += 1
        return self.ledger.append({
            "schema_version": SCHEMA_VERSION,
            "record_type": "REVIEW",
            "review_kind": kind,
            "log_id": f"{record['incident_id']}-R{self._counter:02d}",
            "timestamp": self.clock.iso(),
            "incident_id": record["incident_id"],
            "ref_log_id": record["log_id"],
            "reviewer": reviewer,
            "verdict": verdict,
            "remediation": remediation,
            "comment": comment,
        })

    def post_review(self, record, reviewer, verdict, remediation, comment) -> dict:
        """2단계(실행 후 검토) 행동에 대한 사람의 사후 확인 (제9조)."""
        return self._review("POST_EXECUTION", record, reviewer, verdict, remediation, comment)

    def investigate(self, record, investigator, verdict, remediation, comment) -> dict:
        """사고 조사 결과(사실관계 판정) 기록."""
        return self._review("INCIDENT_INVESTIGATION", record, investigator, verdict, remediation, comment)
