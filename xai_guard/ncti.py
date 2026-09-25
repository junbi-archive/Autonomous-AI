"""NCTI(국가사이버위협정보공유시스템) 연계 모의 클라이언트 (고시안 제5조·제15조).

- anchor    : 원장의 최신 해시를 외부 기관에 주기적으로 등록한다. 기관 내부자가 원장 전체를
              재계산해 변조하더라도, 외부에 등록된 해시와 달라져 탐지된다.
- share_case: 사고 사례를 공유한다. 알고리즘·모델 내부 정보는 제외하고 판단 결과와 근거,
              증거 해시만 담는다 (제14조 영업비밀 보호).
"""

import json
from pathlib import Path

from .ledger import canonical_json, load_records


class NctiClient:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.anchor_path = self.root / "anchors.jsonl"

    def anchor(self, agency_id: str, ledger, at: str) -> dict:
        entry = {"anchored_at": at, "agency_id": agency_id,
                 "seq": ledger.head_seq, "head_hash": ledger.head_hash}
        with self.anchor_path.open("a", encoding="utf-8") as f:
            f.write(canonical_json(entry) + "\n")
        return entry

    def anchors(self) -> list:
        return load_records(self.anchor_path)

    def share_case(self, incident_id: str, records: list, at: str) -> Path:
        verdicts = {}
        for r in records:
            if r["record_type"] == "REVIEW":
                verdicts[r["ref_log_id"]] = r["verdict"]
        actions = []
        for r in records:
            if r["record_type"] != "ACTION":
                continue
            actions.append({
                "log_id": r["log_id"],
                "action_type": r["action"]["type"],
                "target_grade": r["action"]["target_grade"],
                "rationale_summary": r["rationale"]["summary"],
                "confidence": r["confidence"],
                "risk_tier": r["risk"]["tier"],
                "approval_status": r["approval"]["status"],
                "executed": r["execution"]["status"] == "EXECUTED",
                "security_flags": [f["code"] for f in r["security_flags"]],
                "evidence_sha256": [e["sha256"] for e in r["evidence"]],
                "verdict": verdicts.get(r["log_id"]),
            })
        case = {"case_id": f"NCTI-{incident_id}", "shared_at": at, "incident_id": incident_id,
                "note": "알고리즘·모델 내부 정보 제외, 판단 결과·근거·증거 해시만 공유", "actions": actions}
        path = self.root / f"case-{incident_id}.json"
        path.write_text(json.dumps(case, ensure_ascii=False, indent=2), encoding="utf-8")
        return path
