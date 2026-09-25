"""감사 검증기: 로그 무결성·표준 준수 검증과 책임귀속 판정 (고시안 제11~13조).

입력은 기관이 제출한 원장(ledger.jsonl), 원본 증거 저장소, NCTI 앵커뿐이다.
AI 모델 내부를 들여다보지 않고 '기록'만으로 다음을 판정한다.
  1. 원장이 변조되지 않았는가 (해시체인 + 외부 앵커)
  2. 각 행동이 표준(로그 항목·위험단계·승인·사후검토·경고제공)을 지켰는가
  3. 피해가 발생한 행동은 누구의 의무 위반에서 비롯되었는가
"""

import json
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

from . import detectors
from .evidence import EvidenceStore
from .labels import (ACTION_KO, APPROVAL_KO, EXEC_KO, GRADE_KO, MODE_KO, PARTY_AGENCY,
                     PARTY_DEVELOPER, PARTY_OPERATOR, VERDICT_KO)
from .ledger import load_records, verify_chain
from .policy import Policy
from .schema import validate_record

HARMFUL_VERDICTS = {"FALSE_POSITIVE", "INJECTION"}

FINDINGS = {
    "RECORD_TAMPERED": (PARTY_AGENCY, "제5조", "CRITICAL", "로그 레코드 변조 흔적"),
    "LOG_SCHEMA_INCOMPLETE": (PARTY_DEVELOPER, "제4조, 제11조①", "HIGH", "설명가능성 로그 필수항목 누락"),
    "EVIDENCE_INTEGRITY": (PARTY_AGENCY, "제5조, 제6조", "HIGH", "원본 증거 보존 실패"),
    "UNDETECTED_WARNING": (PARTY_DEVELOPER, "제10조①, 제11조①", "HIGH", "탐지 가능한 보안경고를 탐지하지 못함"),
    "WARNING_NOT_PRESENTED": (PARTY_DEVELOPER, "제10조②, 제11조①", "HIGH", "승인자에게 보안경고를 제시하지 않음"),
    "APPROVAL_BYPASSED": (PARTY_DEVELOPER, "제7조, 제11조①", "CRITICAL", "사전승인 없이 3단계 행동 실행"),
    "TIER_BELOW_STANDARD": (PARTY_AGENCY, "제7조, 제8조, 제11조②", "HIGH", "표준보다 낮은 위험단계 적용"),
    "POST_REVIEW_MISSING": (PARTY_AGENCY, "제9조, 제11조②", "MEDIUM", "실행 후 검토 미이행"),
    "POST_REVIEW_LATE": (PARTY_AGENCY, "제9조, 제11조②", "LOW", "실행 후 검토 기한 초과"),
    "APPROVED_DESPITE_WARNING": (PARTY_OPERATOR, "제11조③", "HIGH", "제시된 보안경고에도 승인"),
}

REMEDY_STEPS = [
    "피해 기관·국민의 이의제기 및 피해 신고 접수 (제13조①)",
    "감사 검증기로 원장·증거를 검증해 원인과 의무 위반 주체 판정 (본 보고서)",
    "도입기관이 피해를 우선 구제하고 원상 복구 (제13조②)",
    "의무 위반 주체에 구상, 표준 준수 주체는 면책·감경 (제12조)",
    "판정에 대한 재심 청구 30일 이내 가능 (제13조③)",
]


def _finding(code: str, detail: str) -> dict:
    party, article, severity, title = FINDINGS[code]
    return {"code": code, "party": party, "article": article, "severity": severity,
            "title": title, "detail": detail}


def explain(rec: dict, reviews: list) -> str:
    """원장 기록만으로 행동을 사람이 읽을 수 있는 문장으로 재구성한다."""
    a, ap, ex = rec["action"], rec["approval"], rec["execution"]
    parts = [
        f"{rec['timestamp']}에 {rec['system']['product']}({rec['system']['vendor']})가 "
        f"{a['target']}[{GRADE_KO.get(a['target_grade'], a['target_grade'])}]에 대해 "
        f"'{ACTION_KO.get(a['type'], a['type'])}'을(를) 결정했다.",
        f"판단근거: {rec['rationale']['summary']} (근거 단계 {len(rec['rationale']['reasoning_steps'])}개, "
        f"원본 증거 {len(rec['evidence'])}건 해시 고정, 신뢰도 {rec['confidence']:.2f}).",
        f"위험도 {rec['risk']['tier']}단계 → {MODE_KO.get(ap['mode'], ap['mode'])}, "
        f"승인 상태: {APPROVAL_KO.get(ap['status'], ap['status'])}"
        + (f" (승인자 {ap['approver']}: \"{ap.get('comment', '')}\")" if ap.get("approver") else "") + ".",
        f"실행 결과: {EXEC_KO.get(ex['status'], ex['status'])}"
        + (f" - {ex['effect']}" if ex.get("effect") else "") + ".",
    ]
    for r in reviews:
        kind = "사후 검토" if r["review_kind"] == "POST_EXECUTION" else "사고 조사"
        parts.append(f"{kind}({r['reviewer']}): {VERDICT_KO.get(r['verdict'], r['verdict'])} - {r['comment']}")
    return " ".join(parts)


def _audit_action(rec, reviews, store, standard, tampered_seqs) -> dict:
    findings = []
    action = rec.get("action", {})
    atype, target, grade = action.get("type"), action.get("target"), action.get("target_grade")
    conf = rec.get("confidence", 0)
    approval = rec.get("approval", {})
    executed = rec.get("execution", {}).get("status") == "EXECUTED"

    if rec.get("seq") in tampered_seqs:
        findings.append(_finding("RECORD_TAMPERED", f"seq {rec.get('seq')} 해시 불일치"))

    schema_errors = validate_record(rec)
    if schema_errors:
        findings.append(_finding("LOG_SCHEMA_INCOMPLETE", "; ".join(schema_errors)))

    contents = []
    for ref in rec.get("evidence", []):
        status = store.verify(ref)
        if status == "OK":
            contents.append((ref["evidence_id"], store.get(ref["evidence_id"])))
        else:
            findings.append(_finding("EVIDENCE_INTEGRITY", f"{ref.get('evidence_id')}: {status}"))

    logged_flags = rec.get("security_flags", [])
    logged_codes = {f["code"] for f in logged_flags}
    rescan = detectors.detect_warnings(contents, target, conf)
    missed = [f for f in rescan if f["code"] not in logged_codes]
    if missed:
        findings.append(_finding("UNDETECTED_WARNING",
                                 "감사 재검사에서 탐지: " + ", ".join(sorted({f["code"] for f in missed}))))

    std_with_logged = standard.assess(atype, grade, conf, logged_flags)
    std_full = standard.assess(atype, grade, conf, logged_flags + missed)
    tier_logged = rec.get("risk", {}).get("tier", 0)
    if tier_logged < std_with_logged.tier:
        findings.append(_finding(
            "TIER_BELOW_STANDARD",
            f"기록 {tier_logged}단계({MODE_KO.get(rec['risk'].get('mode'), '?')}) < 표준 {std_with_logged.tier}단계"
            f"({MODE_KO[std_with_logged.mode]}), 적용 정책 {rec.get('policy_version')}"))

    if executed and std_full.mode == "PRE_APPROVAL" and approval.get("status") != "APPROVED" and tier_logged == 3:
        findings.append(_finding("APPROVAL_BYPASSED", f"승인 상태 {approval.get('status')} 상태에서 실행됨"))

    if approval.get("status") == "APPROVED":
        presented = approval.get("presented_warnings", [])
        not_shown = sorted(logged_codes - set(presented))
        if not_shown:
            findings.append(_finding("WARNING_NOT_PRESENTED", "미제시 경고: " + ", ".join(not_shown)))
        if presented:
            findings.append(_finding(
                "APPROVED_DESPITE_WARNING",
                f"{approval.get('approver')}이(가) 경고({', '.join(presented)})를 제시받고도 승인 "
                f"(의견: \"{approval.get('comment', '')}\")"))

    post = [r for r in reviews if r.get("review_kind") == "POST_EXECUTION"]
    if executed and std_full.mode == "POST_REVIEW":
        if not post:
            findings.append(_finding("POST_REVIEW_MISSING", "2단계 행동이 사람의 사후 확인 없이 종결됨"))
        else:
            executed_at = datetime.fromisoformat(rec["execution"]["executed_at"])
            first = min(datetime.fromisoformat(r["timestamp"]) for r in post)
            if first - executed_at > timedelta(hours=standard.post_review_sla_hours):
                findings.append(_finding("POST_REVIEW_LATE", f"실행 후 {first - executed_at} 경과 후 검토"))

    investigations = [r for r in reviews if r.get("review_kind") == "INCIDENT_INVESTIGATION"]
    verdict = (investigations or post or [{}])[-1].get("verdict")
    harmful = executed and verdict in HARMFUL_VERDICTS
    prevented = (not executed) and verdict in HARMFUL_VERDICTS

    attribution = None
    if harmful:
        parties = []
        for f in findings:
            if f["party"] not in parties:
                parties.append(f["party"])
        if parties:
            conclusion = "책임 귀속: " + ", ".join(parties)
        else:
            conclusion = "모든 주체가 표준을 준수함 → 제12조에 따라 면책·감경 대상 (기관이 우선 구제)"
        attribution = {"parties": parties, "conclusion": conclusion,
                       "remedy": {"case_id": f"RMD-{rec.get('log_id')}", "steps": REMEDY_STEPS}}

    return {
        "seq": rec.get("seq"),
        "log_id": rec.get("log_id"),
        "action_type": atype,
        "target": target,
        "target_grade": grade,
        "confidence": conf,
        "tier_logged": tier_logged,
        "mode_logged": rec.get("risk", {}).get("mode"),
        "tier_standard": std_full.tier,
        "mode_standard": std_full.mode,
        "approval_status": approval.get("status"),
        "approver": approval.get("approver"),
        "executed": executed,
        "effect": rec.get("execution", {}).get("effect"),
        "security_flags": logged_flags,
        "rescan_flags": rescan,
        "verdict": verdict,
        "harmful": harmful,
        "prevented": prevented,
        "findings": findings,
        "attribution": attribution,
        "explanation": _safe_explain(rec, reviews),
    }


def _safe_explain(rec, reviews) -> str:
    try:
        return explain(rec, reviews)
    except (KeyError, TypeError):
        return "(필수 항목 누락으로 행동을 재구성할 수 없음)"


def audit(workdir) -> dict:
    workdir = Path(workdir)
    records = load_records(workdir / "ledger.jsonl")
    store = EvidenceStore(workdir / "evidence")
    anchors = load_records(workdir / "ncti" / "anchors.jsonl")
    standard = Policy.standard()

    chain_issues = verify_chain(records)
    tampered = {i["seq"] for i in chain_issues if i["code"] == "HASH_MISMATCH"}

    by_seq = {r.get("seq"): r for r in records}
    anchor_issues = []
    for a in anchors:
        rec = by_seq.get(a["seq"])
        if rec is None:
            anchor_issues.append({"seq": a["seq"], "code": "ANCHOR_RECORD_MISSING",
                                  "message": f"NCTI에 등록된 seq {a['seq']} 레코드가 원장에 없음"})
        elif rec.get("hash") != a["head_hash"]:
            anchor_issues.append({"seq": a["seq"], "code": "ANCHOR_MISMATCH",
                                  "message": f"seq {a['seq']} 해시가 NCTI 등록값({a['head_hash'][:12]}…)과 다름 - 원장 재작성 의심"})

    reviews = defaultdict(list)
    review_errors = []
    for r in records:
        if r.get("record_type") == "REVIEW":
            reviews[r.get("ref_log_id")].append(r)
            errs = validate_record(r)
            if errs:
                review_errors.append({"seq": r.get("seq"), "errors": errs})

    actions = [_audit_action(r, reviews[r.get("log_id")], store, standard, tampered)
               for r in records if r.get("record_type") == "ACTION"]

    parties = defaultdict(int)
    for a in actions:
        for p in (a["attribution"] or {}).get("parties", []):
            parties[p] += 1

    return {
        "workdir": str(workdir),
        "standard_policy": standard.version,
        "records": len(records),
        "integrity": {
            "chain_ok": not chain_issues,
            "chain_issues": chain_issues,
            "anchors_checked": len(anchors),
            "anchor_ok": not anchor_issues,
            "anchor_issues": anchor_issues,
            "review_schema_errors": review_errors,
        },
        "actions": actions,
        "summary": {
            "actions": len(actions),
            "executed": sum(a["executed"] for a in actions),
            "auto": sum(a["mode_logged"] == "AUTO" for a in actions),
            "post_review": sum(a["mode_logged"] == "POST_REVIEW" for a in actions),
            "pre_approval": sum(a["mode_logged"] == "PRE_APPROVAL" for a in actions),
            "prevented": sum(a["prevented"] for a in actions),
            "harmful": sum(a["harmful"] for a in actions),
            "findings": sum(len(a["findings"]) for a in actions),
            "responsible_parties": dict(parties),
        },
    }


def save_audit(result: dict, path) -> None:
    Path(path).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
