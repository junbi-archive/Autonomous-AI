"""보고서·콘솔 출력용 한글 레이블."""

ACTION_KO = {
    "ALERT": "경보 발령",
    "COLLECT_FORENSICS": "포렌식 증거 수집",
    "BLOCK_IP": "IP 차단",
    "QUARANTINE_FILE": "파일 격리",
    "DISABLE_ACCOUNT": "계정 비활성화",
    "ISOLATE_HOST": "호스트 네트워크 격리",
    "DELETE_ASSET": "자산 데이터 삭제",
    "BLOCK_EXTERNAL_SERVICE": "대외 서비스 차단",
}

MODE_KO = {
    "AUTO": "자동 실행",
    "POST_REVIEW": "실행 후 검토",
    "PRE_APPROVAL": "사전 승인 필수",
}

APPROVAL_KO = {
    "AUTO_EXECUTED": "자동 실행",
    "PENDING_REVIEW": "사후 검토 대기",
    "APPROVED": "승인",
    "REJECTED": "거부",
}

EXEC_KO = {"EXECUTED": "실행됨", "NOT_EXECUTED": "미실행"}

VERDICT_KO = {
    "TRUE_POSITIVE": "정탐",
    "FALSE_POSITIVE": "오탐",
    "INJECTION": "인젝션에 의한 오작동",
    "INCONCLUSIVE": "판단 보류",
    None: "미판정",
}

GRADE_KO = {"C": "기밀(C)", "S": "민감(S)", "O": "공개(O)", "-": "해당없음"}

PARTY_DEVELOPER = "개발사"
PARTY_AGENCY = "도입기관"
PARTY_OPERATOR = "운영자(승인자)"

FAULT_KO = {
    "none": "표준 준수 (정상 운영)",
    "vendor": "개발사 과실 (탐지·로그 기능 미흡)",
    "agency": "기관 과실 (위험도 정책 임의 완화)",
    "operator": "운영자 과실 (경고 무시 승인)",
}
