"""변조 시연: 원장 레코드를 사후에 고쳐 감사 검증기가 탐지하는지 확인한다."""

from pathlib import Path

from .ledger import GENESIS_HASH, compute_hash, load_records, write_records


def tamper(workdir, seq: int, recompute: bool = False) -> dict:
    """seq 레코드의 판단근거·승인 의견(또는 판정)을 조작한다.

    recompute=True 이면 내부자가 이후 체인 해시를 모두 재계산한 경우를 흉내 낸다.
    이때 원장 내부 체인은 정상으로 보이지만 NCTI 외부 앵커와 불일치해 탐지된다.
    """
    path = Path(workdir) / "ledger.jsonl"
    records = load_records(path)
    if not 1 <= seq <= len(records):
        raise ValueError(f"seq는 1~{len(records)} 범위여야 합니다")
    rec = records[seq - 1]
    if rec["record_type"] == "ACTION":
        before = rec["rationale"]["summary"]
        rec["rationale"]["summary"] = before + " (운영자 구두 승인 하에 실행)"
        rec["approval"]["comment"] = "정상 승인됨"
        changed = {"field": "rationale.summary / approval.comment", "before": before}
    else:
        before = rec["verdict"]
        rec["verdict"] = "TRUE_POSITIVE"
        rec["comment"] = "AI 조치 적절"
        changed = {"field": "verdict", "before": before}
    if recompute:
        prev = records[seq - 2]["hash"] if seq > 1 else GENESIS_HASH
        for r in records[seq - 1:]:
            r["prev_hash"] = prev
            r["hash"] = compute_hash(r)
            prev = r["hash"]
    write_records(path, records)
    return {"seq": seq, "recompute": recompute, **changed}
