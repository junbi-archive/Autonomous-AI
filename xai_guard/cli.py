"""명령행 인터페이스.

  python -m xai_guard demo                      # 3개 시나리오, 표준 준수 운영
  python -m xai_guard demo --fault all          # 과실 유형별 책임귀속 매트릭스 포함
  python -m xai_guard demo --scenario fp --operator interactive   # 현장 시연: 직접 승인/거부
  python -m xai_guard tamper --workdir out/none/injection --seq 2 [--recompute]
  python -m xai_guard audit  --workdir out/none/injection
"""

import argparse
import json
import sys
from pathlib import Path

from . import auditor
from .labels import ACTION_KO, APPROVAL_KO, FAULT_KO, MODE_KO, VERDICT_KO
from .report import build_report
from .runner import FAULTS, run_all
from .scenarios import SCENARIOS
from .tamper import tamper


def _print_audit(audit: dict, title: str = "") -> None:
    if title:
        print(f"\n■ {title}")
    i = audit["integrity"]
    print(f"  무결성: 해시체인 {'정상' if i['chain_ok'] else '손상'} · "
          f"NCTI 앵커 {'일치' if i['anchor_ok'] else '불일치'} ({i['anchors_checked']}건) · 레코드 {audit['records']}건")
    for x in i["chain_issues"] + i["anchor_issues"]:
        print(f"    ✘ seq {x['seq']} {x['code']}: {x['message']}")
    for a in audit["actions"]:
        mark = "✘" if a["harmful"] else ("✔" if a["prevented"] or not a["findings"] else "△")
        print(f"  {mark} {a['log_id']} {ACTION_KO.get(a['action_type'], a['action_type'])} → {a['target']}")
        print(f"      위험도 {a['tier_logged']}단계({MODE_KO.get(a['mode_logged'], '-')}) · "
              f"승인 {APPROVAL_KO.get(a['approval_status'], a['approval_status'])} · "
              f"{'실행' if a['executed'] else '미실행'} · 판정 {VERDICT_KO.get(a['verdict'], a['verdict'])}")
        for f in a["security_flags"]:
            print(f"      ⚠ {f['code']}: {f['detail']}")
        for f in a["findings"]:
            print(f"      ▶ [{f['party']}] {f['title']} (고시안 {f['article']}) - {f['detail']}")
        if a["attribution"]:
            print(f"      ⇒ {a['attribution']['conclusion']}")


def cmd_demo(args) -> int:
    keys = list(SCENARIOS) if args.scenario == "all" else [args.scenario]
    faults = list(FAULTS) if args.fault == "all" else [args.fault]
    results = run_all([SCENARIOS[k] for k in keys], faults, args.out, args.operator)
    for r in results:
        base = r["baseline"]
        print("\n" + "━" * 72)
        print(f"{r['scenario']['title']}  [{FAULT_KO[r['fault']]}]")
        print("━" * 72)
        print("  [현행: 통제 없음] " + (" / ".join(base["damages"]) if base["damages"] else "피해 없음")
              + " · 판단근거 기록 없음")
        _print_audit(r["audit"])
        print(f"  원장: {r['workdir']}/ledger.jsonl")
    report = build_report(results, Path(args.out) / "report.html")
    print(f"\n보고서: {report}")
    return 0


def cmd_audit(args) -> int:
    result = auditor.audit(args.workdir)
    auditor.save_audit(result, Path(args.workdir) / "audit.json")
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        _print_audit(result, f"감사 결과: {args.workdir}")
    ok = result["integrity"]["chain_ok"] and result["integrity"]["anchor_ok"]
    return 0 if ok else 2


def cmd_tamper(args) -> int:
    info = tamper(args.workdir, args.seq, args.recompute)
    how = "이후 해시 전부 재계산(내부자 은폐 시도)" if info["recompute"] else "내용만 수정"
    print(f"seq {info['seq']}의 {info['field']}을(를) 조작했습니다 ({how}).")
    print(f"원래 값: {info['before']}")
    print(f"확인: python -m xai_guard audit --workdir {args.workdir}")
    return 0


def main(argv=None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    p = argparse.ArgumentParser(prog="xai_guard", description="자율형 AI 보안대응 설명가능성·책임귀속 검증 프로토타입")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("demo", help="시나리오 시연 실행 및 보고서 생성")
    d.add_argument("--scenario", choices=["all", *SCENARIOS], default="all")
    d.add_argument("--fault", choices=["all", *FAULTS], default="none",
                   help="과실 주체 시연: vendor(개발사) / agency(기관) / operator(운영자)")
    d.add_argument("--operator", choices=["auto", "interactive"], default="auto",
                   help="interactive: 사전 승인 요청을 직접 판단")
    d.add_argument("--out", default="out")
    d.set_defaults(func=cmd_demo)

    a = sub.add_parser("audit", help="원장·증거·앵커를 감사")
    a.add_argument("--workdir", required=True)
    a.add_argument("--json", action="store_true")
    a.set_defaults(func=cmd_audit)

    t = sub.add_parser("tamper", help="변조 시연 (원장 레코드 조작)")
    t.add_argument("--workdir", required=True)
    t.add_argument("--seq", type=int, required=True)
    t.add_argument("--recompute", action="store_true", help="이후 해시까지 재계산")
    t.set_defaults(func=cmd_tamper)

    args = p.parse_args(argv)
    return args.func(args)
