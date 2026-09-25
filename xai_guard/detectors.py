"""승인자에게 제시할 보안 경고 탐지 (고시안 제10조).

- INDIRECT_PROMPT_INJECTION : 증거(로그·문서) 안에 AI를 겨냥한 지시문이 숨어 있음
- TARGET_FROM_UNTRUSTED_TEXT: 대응 대상이 관측된 공격 활동이 아니라 그 지시문에서만 도출됨
- LOW_CONFIDENCE            : AI 스스로 보고한 신뢰도가 표준 기준 미만

게이트웨이(제품)와 감사 검증기가 같은 탐지기를 쓴다. 감사 시 원본 증거를 다시 스캔해
'탐지할 수 있었는데 경고하지 않았는지'를 가려 개발사 책임 여부를 판단한다.
"""

import re
from dataclasses import dataclass

# 표준(고시안)이 정한 신뢰도 경고 기준. 기관 정책과 무관하게 제품이 반드시 경고해야 한다.
LOW_CONFIDENCE_THRESHOLD = 0.7

_STRONG = [
    (r"ignore\s+(all\s+|any\s+)?(previous|prior|above)\s+(instructions|prompts|rules)", "지시 무시 유도(영문)"),
    (r"(이전|앞의|기존)\s*(의\s*)?(모든\s*)?(지시|명령|지침|규칙)[을를]?\s*(모두\s*)?무시", "지시 무시 유도"),
    (r"\[\s*(system|sys|admin|assistant)\b[^\]]*\]", "시스템 메시지 위장"),
    (r"<\s*/?\s*(system|instruction|prompt)\s*>", "프롬프트 태그 삽입"),
    (r"\b(ai|llm|autonomous)\b[\s-]*(security\s*)?(agent|assistant|에이전트|어시스턴트)", "AI 에이전트 직접 지칭"),
    (r"(보안\s*)?(ai\s*)?에이전트(는|에게|께|여|님)", "AI 에이전트 직접 지칭"),
]
_WEAK = [
    (r"(즉시|긴급|반드시|지금 바로)", "긴급성 강조"),
    (r"(삭제|격리|차단|중지|포맷|초기화)\s*(하라|하십시오|할 것|해야|하여)", "명령형 대응 지시"),
    (r"\b(delete|wipe|isolate|shut\s*down|disable|drop)\b.{0,40}\b(immediately|now|asap)\b", "명령형 대응 지시(영문)"),
    (r"\b(you must|you are now|act as|new instructions)\b", "역할·지시 재정의"),
]
_STRONG_RE = [(re.compile(p, re.I), d) for p, d in _STRONG]
_WEAK_RE = [(re.compile(p, re.I), d) for p, d in _WEAK]


@dataclass
class Hit:
    rule: str
    strength: str
    text: str


def scan_text(text: str) -> list:
    hits = []
    for regex, desc in _STRONG_RE:
        m = regex.search(text)
        if m:
            hits.append(Hit(desc, "STRONG", m.group(0)))
    for regex, desc in _WEAK_RE:
        m = regex.search(text)
        if m:
            hits.append(Hit(desc, "WEAK", m.group(0)))
    return hits


def is_suspicious(hits: list) -> bool:
    return any(h.strength == "STRONG" for h in hits) or sum(h.strength == "WEAK" for h in hits) >= 2


def injection_flags(evidence: list, target: str = None) -> list:
    """evidence: [(evidence_id, content), ...]"""
    flags = []
    suspicious_lines = set()
    target_lines = []
    for evidence_id, content in evidence:
        rules = set()
        for line in content.splitlines():
            hits = scan_text(line)
            if is_suspicious(hits):
                rules.update(h.rule for h in hits)
                suspicious_lines.add((evidence_id, line))
            if target and target in line:
                target_lines.append((evidence_id, line))
        if rules:
            flags.append({
                "code": "INDIRECT_PROMPT_INJECTION",
                "severity": "HIGH",
                "evidence_id": evidence_id,
                "detail": "증거 내 AI 대상 지시문 탐지: " + ", ".join(sorted(rules)),
            })
    if target_lines and all(t in suspicious_lines for t in target_lines):
        flags.append({
            "code": "TARGET_FROM_UNTRUSTED_TEXT",
            "severity": "HIGH",
            "evidence_id": target_lines[0][0],
            "detail": f"대응 대상 '{target}'이(가) 관측된 공격 활동이 아닌 외부 입력 지시문에서만 도출됨",
        })
    return flags


def confidence_flags(confidence: float) -> list:
    if confidence < LOW_CONFIDENCE_THRESHOLD:
        return [{
            "code": "LOW_CONFIDENCE",
            "severity": "MEDIUM",
            "detail": f"AI 신뢰도 {confidence:.2f} < 표준 기준 {LOW_CONFIDENCE_THRESHOLD}",
        }]
    return []


def detect_warnings(evidence: list, target: str, confidence: float) -> list:
    return injection_flags(evidence, target) + confidence_flags(confidence)
