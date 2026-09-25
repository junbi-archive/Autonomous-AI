"""해시체인 기반 append-only 로그 원장 (고시안 제5조).

각 레코드는 직전 레코드의 해시(prev_hash)를 포함하고, 자신의 해시는
'hash' 필드를 제외한 정규화 JSON의 SHA-256 값이다. 따라서 레코드 하나를
수정·삭제·삽입하면 그 지점부터 체인 검증이 실패한다.
"""

import hashlib
import json
from pathlib import Path

GENESIS_HASH = "0" * 64


def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def compute_hash(record: dict) -> str:
    body = {k: v for k, v in record.items() if k != "hash"}
    return hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()


def load_records(path) -> list:
    path = Path(path)
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def write_records(path, records) -> None:
    with Path(path).open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(canonical_json(rec) + "\n")


class HashChainLedger:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._records = load_records(self.path)

    @property
    def head_hash(self) -> str:
        return self._records[-1]["hash"] if self._records else GENESIS_HASH

    @property
    def head_seq(self) -> int:
        return self._records[-1]["seq"] if self._records else 0

    def append(self, record: dict) -> dict:
        rec = dict(record)
        rec["seq"] = self.head_seq + 1
        rec["prev_hash"] = self.head_hash
        rec.pop("hash", None)
        rec["hash"] = compute_hash(rec)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(canonical_json(rec) + "\n")
        self._records.append(rec)
        return rec

    def records(self) -> list:
        return list(self._records)


def verify_chain(records) -> list:
    """체인 무결성 검증. 문제가 없으면 빈 리스트를 반환한다."""
    issues = []
    prev = GENESIS_HASH
    for expected_seq, rec in enumerate(records, 1):
        seq = rec.get("seq")
        if seq != expected_seq:
            issues.append({"seq": seq, "code": "SEQ_GAP",
                           "message": f"순번 불연속 (기대 {expected_seq}, 실제 {seq}) - 레코드 삭제·삽입 의심"})
        if rec.get("prev_hash") != prev:
            issues.append({"seq": seq, "code": "PREV_HASH_MISMATCH",
                           "message": "직전 레코드 해시와 연결되지 않음 - 삭제·삽입·재배열 의심"})
        if rec.get("hash") != compute_hash(rec):
            issues.append({"seq": seq, "code": "HASH_MISMATCH",
                           "message": "레코드 내용이 기록 이후 변경됨 - 변조 의심"})
        prev = rec.get("hash")
    return issues
