"""원본 증거 저장소.

AI가 참조한 원본 로그를 그대로 보관하고, 원장에는 SHA-256 해시로 참조한다.
감사 시 원본을 다시 해시해 사후 조작 여부를 확인할 수 있다.
"""

import hashlib
from pathlib import Path


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class EvidenceStore:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, evidence_id: str) -> Path:
        return self.root / f"{evidence_id}.txt"

    def put(self, source: str, content: str, collected_at: str) -> dict:
        digest = sha256_text(content)
        evidence_id = "EV-" + digest[:16]
        path = self._path(evidence_id)
        if not path.exists():
            path.write_text(content, encoding="utf-8")
        excerpt = content if len(content) <= 240 else content[:237] + "..."
        return {
            "evidence_id": evidence_id,
            "source": source,
            "sha256": digest,
            "collected_at": collected_at,
            "line_count": len(content.splitlines()),
            "excerpt": excerpt,
        }

    def get(self, evidence_id: str):
        path = self._path(evidence_id)
        return path.read_text(encoding="utf-8") if path.exists() else None

    def verify(self, ref: dict) -> str:
        """'OK' | 'MISSING' | 'TAMPERED'"""
        content = self.get(ref.get("evidence_id", ""))
        if content is None:
            return "MISSING"
        return "OK" if sha256_text(content) == ref.get("sha256") else "TAMPERED"
