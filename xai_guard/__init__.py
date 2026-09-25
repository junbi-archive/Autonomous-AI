"""XAI-Guard: 자율형 AI 보안대응의 설명가능성·책임귀속 검증 프로토타입.

정책 제안서 Ⅴ-3 '검증 프로토타입'의 구현체로, 세 가지 구성요소로 이루어진다.

1. 설명가능성 로그 스키마(XAL) + 해시체인 원장   -> schema.py, ledger.py, evidence.py
2. 위험도별 인간개입 게이트웨이                  -> policy.py, detectors.py, gateway.py
3. 감사 검증기(무결성·준수·책임귀속)             -> auditor.py
"""

__version__ = "0.1.0"
