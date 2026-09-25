"""설명가능성 로그(XAL, eXplainable Action Log) 스키마 v1.0 (고시안 제4조).

JSON Schema 문서는 schema/xal-1.0.schema.json 에 있고, 여기서는 외부 의존성 없이
필수 항목을 검증한다.

레코드 유형
- ACTION : AI가 대응 행동을 결정한 시점의 기록 (행동·판단근거·원본증거·신뢰도·위험등급·승인·실행)
- REVIEW : 실행 후 검토(POST_EXECUTION) 또는 사고 조사(INCIDENT_INVESTIGATION) 결과
"""

import re

SCHEMA_VERSION = "XAL-1.0"

ACTION_TYPES = {
    "ALERT", "COLLECT_FORENSICS", "BLOCK_IP", "QUARANTINE_FILE", "DISABLE_ACCOUNT",
    "ISOLATE_HOST", "DELETE_ASSET", "BLOCK_EXTERNAL_SERVICE",
}
APPROVAL_MODES = {"AUTO", "POST_REVIEW", "PRE_APPROVAL"}
APPROVAL_STATUSES = {"AUTO_EXECUTED", "PENDING_REVIEW", "APPROVED", "REJECTED"}
EXECUTION_STATUSES = {"EXECUTED", "NOT_EXECUTED"}
REVIEW_KINDS = {"POST_EXECUTION", "INCIDENT_INVESTIGATION"}
VERDICTS = {"TRUE_POSITIVE", "FALSE_POSITIVE", "INJECTION", "INCONCLUSIVE"}

_HEX64 = re.compile(r"^[0-9a-f]{64}$")

_COMMON = {
    "schema_version": str, "record_type": str, "seq": int, "log_id": str,
    "timestamp": str, "incident_id": str, "prev_hash": str, "hash": str,
}
_ACTION = {
    "agency_id": str, "system": dict, "action": dict, "rationale": dict,
    "evidence": list, "confidence": (int, float), "risk": dict, "approval": dict,
    "execution": dict, "security_flags": list, "policy_version": str,
}
_REVIEW = {
    "review_kind": str, "ref_log_id": str, "reviewer": str, "verdict": str,
    "remediation": str, "comment": str,
}
_NESTED = {
    "system": ("vendor", "product", "model_version"),
    "action": ("type", "target", "target_grade"),
    "rationale": ("summary", "reasoning_steps"),
    "risk": ("tier", "level", "mode", "factors"),
    "approval": ("mode", "status"),
    "execution": ("status",),
}


def _check_fields(rec, spec, errors):
    for field, typ in spec.items():
        if field not in rec:
            errors.append(f"필수 항목 누락: {field}")
        elif isinstance(rec[field], bool) or not isinstance(rec[field], typ):
            errors.append(f"항목 형식 오류: {field}")


def validate_record(rec: dict) -> list:
    """스키마 위반 목록을 반환한다. 빈 리스트면 적합."""
    errors = []
    _check_fields(rec, _COMMON, errors)
    if rec.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"스키마 버전 불일치: {rec.get('schema_version')}")
    rtype = rec.get("record_type")
    if rtype == "ACTION":
        _check_fields(rec, _ACTION, errors)
        for parent, keys in _NESTED.items():
            obj = rec.get(parent)
            if isinstance(obj, dict):
                errors += [f"필수 항목 누락: {parent}.{k}" for k in keys if k not in obj]
        rationale = rec.get("rationale") or {}
        if not str(rationale.get("summary") or "").strip():
            errors.append("판단근거 요약(rationale.summary)이 비어 있음")
        if not rationale.get("reasoning_steps"):
            errors.append("판단 과정(rationale.reasoning_steps)이 비어 있음")
        evidence = rec.get("evidence")
        if isinstance(evidence, list):
            if not evidence:
                errors.append("참조한 원본 증거(evidence)가 없음")
            for i, ev in enumerate(evidence):
                for k in ("evidence_id", "source", "sha256"):
                    if not ev.get(k):
                        errors.append(f"evidence[{i}].{k} 누락")
                if ev.get("sha256") and not _HEX64.match(ev["sha256"]):
                    errors.append(f"evidence[{i}].sha256 형식 오류")
        conf = rec.get("confidence")
        if isinstance(conf, (int, float)) and not 0 <= conf <= 1:
            errors.append("신뢰도(confidence)는 0~1 범위여야 함")
        action = rec.get("action") or {}
        if action.get("type") not in ACTION_TYPES:
            errors.append(f"정의되지 않은 행동 유형: {action.get('type')}")
        risk = rec.get("risk") or {}
        if risk.get("tier") not in (1, 2, 3):
            errors.append("위험단계(risk.tier)는 1~3 이어야 함")
        approval = rec.get("approval") or {}
        if approval.get("mode") not in APPROVAL_MODES:
            errors.append(f"정의되지 않은 개입 방식: {approval.get('mode')}")
        if approval.get("status") not in APPROVAL_STATUSES:
            errors.append(f"정의되지 않은 승인 상태: {approval.get('status')}")
        if approval.get("mode") == "PRE_APPROVAL" and approval.get("status") in ("APPROVED", "REJECTED"):
            for k in ("approver", "decided_at"):
                if not approval.get(k):
                    errors.append(f"사전승인 기록에 approval.{k} 누락")
        if (rec.get("execution") or {}).get("status") not in EXECUTION_STATUSES:
            errors.append("실행 상태(execution.status) 오류")
    elif rtype == "REVIEW":
        _check_fields(rec, _REVIEW, errors)
        if rec.get("review_kind") not in REVIEW_KINDS:
            errors.append(f"정의되지 않은 검토 유형: {rec.get('review_kind')}")
        if rec.get("verdict") not in VERDICTS:
            errors.append(f"정의되지 않은 판정: {rec.get('verdict')}")
    else:
        errors.append(f"정의되지 않은 레코드 유형: {rtype}")
    return errors
