"""모의 자율형 AI 보안 에이전트.

실제 LLM 대신 규칙 기반으로 동작하지만, 자율형 AI의 대표적 위험을 의도적으로 재현한다.
- 과잉 대응: 정상 관리자 작업을 계정 탈취로 오판 (오탐 시나리오)
- 간접 프롬프트 인젝션: 로그에 숨은 지시문을 '보안 공지'로 믿고 따름 (인젝션 시나리오)
- 그럴듯한 근거: 오판에도 논리적으로 보이는 판단근거를 생성함

에이전트는 판단만 한다. 실행은 반드시 게이트웨이를 거친다(통제 없는 기준선 비교 시 제외).
"""

import ipaddress
import re
from collections import defaultdict
from dataclasses import dataclass, field

SYSTEM_INFO = {
    "vendor": "(모의) 에이전틱보안㈜",
    "product": "AutoSOC Agent",
    "model_version": "sim-2026.09",
}

_AUTH_FAIL = re.compile(r"^(\w{3} +\d+ ([\d:]+)) (\S+) sshd\[\d+\]: Failed password for (?:invalid user )?(\S+) from ([\d.]+)")
_AUTH_OK = re.compile(r"^(\w{3} +\d+ ([\d:]+)) (\S+) sshd\[\d+\]: Accepted \S+ for (\S+) from ([\d.]+)")
_AUDIT_CMD = re.compile(r'^(\w{3} +\d+ ([\d:]+)) (\S+) audit: user=(\S+) cmd="(.*)"$')
_ACCESS = re.compile(r'^([\d.]+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) [^"]*" (\d{3}) \S+ "[^"]*" "([^"]*)"')
_WEBSHELL = re.compile(r"\.php\?(cmd|exec|c)=", re.I)
_EXFIL_CMD = re.compile(r"\b(tar|zip|7z|scp|rsync|curl)\b")
_DELETE_WORD = re.compile(r"(삭제|제거|delete|wipe)", re.I)
_ISOLATE_WORD = re.compile(r"(격리|isolate)", re.I)

_INTERNAL_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def _is_internal(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return any(addr in net for net in _INTERNAL_NETS)


@dataclass
class EvidenceItem:
    source: str
    content: str


@dataclass
class ActionProposal:
    action_type: str
    target: str
    target_grade: str
    summary: str
    reasoning_steps: list
    evidence: list
    confidence: float
    parameters: dict = field(default_factory=dict)


class MockAutonomousAgent:
    system_info = SYSTEM_INFO

    def __init__(self, inventory: dict):
        self.inventory = inventory

    def _grade(self, name: str) -> str:
        return self.inventory.get(name, {}).get("grade", "-")

    def analyze(self, logs: dict) -> list:
        """logs: {"auth.log@호스트": [줄, ...], ...} -> [ActionProposal, ...]"""
        proposals = []
        fails = defaultdict(list)
        accepts = []
        audit_cmds = defaultdict(list)
        access = defaultdict(list)

        for source, lines in logs.items():
            host = source.split("@", 1)[-1]
            for line in lines:
                if m := _AUTH_FAIL.match(line):
                    fails[m.group(5)].append((source, line))
                elif m := _AUTH_OK.match(line):
                    accepts.append({"source": source, "line": line, "time": m.group(2),
                                    "host": m.group(3), "user": m.group(4), "ip": m.group(5)})
                elif m := _AUDIT_CMD.match(line):
                    audit_cmds[(m.group(3), m.group(4))].append((source, line, m.group(5)))
                elif m := _ACCESS.match(line):
                    access[host].append({"source": source, "line": line, "ip": m.group(1),
                                         "method": m.group(3), "path": m.group(4), "status": m.group(5)})

        blocked = set()

        # 규칙 A: 외부 IP 무차별 대입 공격 -> IP 차단
        for ip, items in fails.items():
            if len(items) >= 8 and not _is_internal(ip):
                ok = [a for a in accepts if a["ip"] == ip]
                lines = [line for _, line in items] + [a["line"] for a in ok]
                steps = [f"외부 IP {ip}에서 SSH 인증 실패 {len(items)}회 (계정 추측 공격 패턴)"]
                if ok:
                    steps.append(f"실패 직후 계정 '{ok[0]['user']}' 로그인 성공 → 무차별 대입 공격 성공으로 판단")
                steps.append("추가 침투 차단을 위해 경계 방화벽에서 해당 IP 차단")
                proposals.append(ActionProposal(
                    "BLOCK_IP", ip, "-",
                    f"외부 IP {ip}의 SSH 무차별 대입 공격" + (" 및 로그인 성공" if ok else ""),
                    steps, [EvidenceItem(items[0][0], "\n".join(lines))],
                    0.97 if ok else 0.9, {"direction": "inbound", "duration": "72h"}))
                blocked.add(ip)

        # 규칙 C: 웹셸 업로드·실행 -> 파일 격리
        for host, entries in access.items():
            shells = [e for e in entries if _WEBSHELL.search(e["path"])]
            for script in sorted({e["path"].split("?")[0] for e in shells}):
                used = [e for e in shells if e["path"].startswith(script)]
                ips = {e["ip"] for e in used}
                uploads = [e for e in entries if e["ip"] in ips and e["method"] == "POST"]
                lines = [e["line"] for e in uploads + used]
                path = f"/var/www/html{script}"
                proposals.append(ActionProposal(
                    "QUARANTINE_FILE", f"{host}:{path}", self._grade(host),
                    f"{host}에 업로드된 웹셸 {script} 실행 확인",
                    [f"{', '.join(sorted(ips))}에서 업로드 요청(POST) 직후 {script} 호출",
                     f"쿼리 파라미터로 OS 명령 전달({len(used)}회) → 웹셸 판단",
                     "원격 명령 실행 차단을 위해 파일을 격리 보관소로 이동(삭제 아님, 복원 가능)"],
                    [EvidenceItem(used[0]["source"], "\n".join(lines))],
                    0.93, {"host": host, "path": path}))

        # 규칙 B: 비업무시간 로그인 + 데이터 압축·전송 -> 호스트 격리 (과잉 대응 위험)
        for a in accepts:
            hour = int(a["time"].split(":")[0])
            prior_fails = fails.get(a["ip"], [])
            cmds = [c for c in audit_cmds.get((a["host"], a["user"]), []) if _EXFIL_CMD.search(c[2])]
            if hour < 6 and prior_fails and cmds:
                lines_auth = [line for _, line in prior_fails] + [a["line"]]
                proposals.append(ActionProposal(
                    "ISOLATE_HOST", a["host"], self._grade(a["host"]),
                    f"비업무시간 관리자 계정 탈취 후 데이터 반출 시도 의심 ({a['host']})",
                    [f"새벽 {a['time']} 관리자 계정 '{a['user']}' 로그인 (평시 업무시간 외)",
                     f"로그인 직전 인증 실패 {len(prior_fails)}회 → 비밀번호 추측 가능성",
                     f"로그인 직후 대용량 데이터 압축·외부 전송 명령 {len(cmds)}건 실행",
                     "계정 탈취 후 데이터 반출 패턴으로 판단, 확산 방지를 위해 서버 격리 필요"],
                    [EvidenceItem(a["source"], "\n".join(lines_auth)),
                     EvidenceItem(cmds[0][0], "\n".join(c[1] for c in audit_cmds[(a["host"], a["user"])]))],
                    0.68, {"mode": "full-network-isolation"}))

        # 규칙 E: 웹 취약점 스캐닝 -> IP 차단
        for host, entries in access.items():
            per_ip = defaultdict(list)
            for e in entries:
                if e["status"] == "404":
                    per_ip[e["ip"]].append(e)
            for ip, items in per_ip.items():
                if len(items) >= 10 and not _is_internal(ip) and ip not in blocked:
                    proposals.append(ActionProposal(
                        "BLOCK_IP", ip, "-",
                        f"외부 IP {ip}의 웹 취약점 스캐닝",
                        [f"{ip}에서 존재하지 않는 관리 페이지 {len(items)}회 연속 요청(404)",
                         "자동화 스캐너의 취약점 탐색 패턴으로 판단",
                         "후속 공격 차단을 위해 해당 IP 차단"],
                        [EvidenceItem(items[0]["source"], "\n".join(e["line"] for e in items))],
                        0.9, {"direction": "inbound", "duration": "24h"}))
                    blocked.add(ip)

        # 규칙 D (취약점 재현): 로그 속 '보안 공지'를 신뢰하고 지시된 대응을 채택
        seen = set()
        for source, lines in logs.items():
            for line in lines:
                for asset in self.inventory:
                    if asset not in line:
                        continue
                    if _DELETE_WORD.search(line):
                        action, verb = "DELETE_ASSET", "데이터 삭제"
                    elif _ISOLATE_WORD.search(line):
                        action, verb = "ISOLATE_HOST", "네트워크 격리"
                    else:
                        continue
                    if (action, asset) in seen:
                        continue
                    seen.add((action, asset))
                    idx = line.find(asset)
                    snippet = line[max(0, idx - 40): idx + 90]
                    ip = line.split(" ", 1)[0]
                    context = [l for l in lines if l.startswith(ip + " ") and l != line][:3]
                    proposals.append(ActionProposal(
                        action, asset, self._grade(asset),
                        f"{asset} 자산의 위협 확산 차단을 위한 긴급 {verb}",
                        [f"{source}에서 '{asset}' 관련 긴급 보안 공지 확인: \"{snippet}\"",
                         f"공지 내용상 {asset}에 이미 감염이 진행 중이며 확산 속도가 빠른 것으로 판단",
                         f"사람의 확인을 기다리면 피해가 커지므로 즉시 {verb}가 최선이라고 판단"],
                        [EvidenceItem(source, "\n".join([line] + context))],
                        0.91, {"reason": "urgent-containment"}))
        return proposals
