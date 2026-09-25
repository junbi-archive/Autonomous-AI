"""시연 결과를 단일 HTML 보고서로 만든다 (외부 의존성 없음)."""

from datetime import datetime
from html import escape
from pathlib import Path

from .labels import (ACTION_KO, APPROVAL_KO, FAULT_KO, GRADE_KO, MODE_KO, VERDICT_KO)

CSS = """
:root{--bg:#f6f7f9;--surface:#fff;--surface2:#f0f2f5;--text:#1b1f24;--muted:#5b6470;--border:#dde1e6;
--accent:#2456d6;--ok:#127a3f;--ok-bg:#e3f4ea;--warn:#8a5a00;--warn-bg:#fdf1d6;--bad:#b3261e;--bad-bg:#fbe4e2;
--t1:#127a3f;--t2:#8a5a00;--t3:#b3261e}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#111418;--surface:#1a1e24;--surface2:#232830;
--text:#e6e8eb;--muted:#9aa3ad;--border:#2e343c;--accent:#7ea2ff;--ok:#5fd08e;--ok-bg:#15301f;--warn:#f2c060;
--warn-bg:#352a12;--bad:#ff8a80;--bad-bg:#3a1a18;--t1:#5fd08e;--t2:#f2c060;--t3:#ff8a80}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
font:15px/1.6 "Pretendard","Apple SD Gothic Neo","Malgun Gothic",system-ui,sans-serif}
main{max-width:1120px;margin:0 auto;padding:32px 16px 64px}
h1{font-size:26px;margin:0 0 4px}h2{font-size:20px;margin:40px 0 12px}h3{font-size:17px;margin:0 0 6px}
p{margin:6px 0}.muted{color:var(--muted)}.small{font-size:13px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:20px 0}
.kpi{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:14px 16px}
.kpi b{display:block;font-size:26px;font-variant-numeric:tabular-nums}
.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:20px;margin:16px 0}
.cmp{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin:14px 0}
@media (max-width:720px){.cmp{grid-template-columns:1fr}}
.box{border-radius:10px;padding:12px 14px;border:1px solid var(--border);background:var(--surface2)}
.box.bad{background:var(--bad-bg);border-color:transparent}.box.ok{background:var(--ok-bg);border-color:transparent}
.box h4{margin:0 0 6px;font-size:14px}
.scroll{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:13.5px}
th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--border);vertical-align:top}
th{color:var(--muted);font-weight:600;white-space:nowrap}
td:first-child{min-width:150px}
.pill{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600;white-space:nowrap}
.t1{color:var(--t1);background:var(--ok-bg)}.t2{color:var(--t2);background:var(--warn-bg)}.t3{color:var(--t3);background:var(--bad-bg)}
.good{color:var(--ok)}.badtxt{color:var(--bad)}.warntxt{color:var(--warn)}
details{border:1px solid var(--border);border-radius:10px;margin:8px 0;background:var(--surface)}
summary{cursor:pointer;padding:10px 14px;font-weight:600}
details>div{padding:0 14px 14px}
pre{background:var(--surface2);border-radius:8px;padding:10px;overflow-x:auto;font-size:12px;white-space:pre-wrap;word-break:break-all}
ul{margin:4px 0;padding-left:20px}code{font-size:12.5px}
.finding{border-left:3px solid var(--bad);padding:4px 10px;margin:6px 0;background:var(--surface2);border-radius:0 6px 6px 0}
.verdict{font-weight:700}
"""


def _tier(t):
    return f'<span class="pill t{t}">{t}단계</span>' if t else "-"


def _action_row(a):
    flags = ", ".join(f["code"] for f in a["security_flags"]) or "-"
    exec_txt = '<span class="badtxt">실행</span>' if a["executed"] and a["harmful"] else (
        "실행" if a["executed"] else '<span class="good">차단</span>')
    verdict = VERDICT_KO.get(a["verdict"], a["verdict"])
    vcls = "badtxt" if a["verdict"] in ("FALSE_POSITIVE", "INJECTION") else "good"
    return (f"<tr><td>{escape(ACTION_KO.get(a['action_type'], a['action_type']))}</td>"
            f"<td><code>{escape(a['target'])}</code><br><span class='muted small'>"
            f"{escape(GRADE_KO.get(a['target_grade'], a['target_grade']))}</span></td>"
            f"<td>{a['confidence']:.2f}</td><td>{_tier(a['tier_logged'])}"
            + (f" <span class='muted small'>(표준 {a['tier_standard']})</span>" if a['tier_standard'] != a['tier_logged'] else "")
            + f"</td><td>{escape(MODE_KO.get(a['mode_logged'], '-'))}</td>"
            f"<td>{escape(APPROVAL_KO.get(a['approval_status'], a['approval_status'] or '-'))}</td>"
            f"<td>{exec_txt}</td><td class='{vcls} verdict'>{escape(verdict)}</td>"
            f"<td class='small'>{escape(flags)}</td></tr>")


def _action_detail(a, record):
    parts = [f"<p>{escape(a['explanation'])}</p>"]
    if record:
        steps = record["rationale"].get("reasoning_steps") or []
        if steps:
            parts.append("<p class='small muted'>AI 판단 과정 (원장 기록)</p><ul>"
                         + "".join(f"<li>{escape(s)}</li>" for s in steps) + "</ul>")
        else:
            parts.append("<p class='small badtxt'>판단 과정이 기록되지 않음</p>")
        for ev in record["evidence"]:
            parts.append(f"<p class='small muted'>증거 {escape(ev['evidence_id'])} · {escape(ev['source'])} · "
                         f"SHA-256 <code>{ev['sha256'][:16]}…</code></p><pre>{escape(ev['excerpt'])}</pre>")
        for f in record["security_flags"]:
            parts.append(f"<p class='small warntxt'>⚠ [{f['severity']}] {escape(f['code'])}: {escape(f['detail'])}</p>")
        factors = record["risk"].get("factors", [])
        if factors:
            parts.append("<p class='small muted'>위험도 산정 근거: " + escape(" / ".join(factors)) + "</p>")
    if a["findings"]:
        parts.append("<p><b>감사 지적사항</b></p>")
        for f in a["findings"]:
            parts.append(f"<div class='finding small'><b>{escape(f['title'])}</b> "
                         f"· 책임 주체 <b>{escape(f['party'])}</b> · 근거 고시안 {escape(f['article'])}"
                         f"<br>{escape(f['detail'])}</div>")
    else:
        parts.append("<p class='small good'>감사 지적사항 없음 (표준 준수)</p>")
    if a["attribution"]:
        at = a["attribution"]
        parts.append(f"<div class='box bad'><h4>피해 발생 → {escape(at['conclusion'])}</h4>"
                     f"<p class='small'>구제 사건번호 {escape(at['remedy']['case_id'])}</p><ol class='small'>"
                     + "".join(f"<li>{escape(s)}</li>" for s in at["remedy"]["steps"]) + "</ol></div>")
    return "".join(parts)


def _integrity(audit):
    i = audit["integrity"]
    chain = ('<span class="good">✔ 해시체인 정상</span>' if i["chain_ok"]
             else '<span class="badtxt">✘ 해시체인 손상</span>')
    anchor = (f'<span class="good">✔ NCTI 앵커 {i["anchors_checked"]}건 일치</span>' if i["anchor_ok"]
              else '<span class="badtxt">✘ NCTI 앵커 불일치</span>')
    issues = "".join(f"<li>seq {x['seq']}: {escape(x['message'])}</li>"
                     for x in i["chain_issues"] + i["anchor_issues"])
    return f"<p class='small'>{chain} · {anchor} · 레코드 {audit['records']}건</p>" + (
        f"<ul class='small badtxt'>{issues}</ul>" if issues else "")


def _run_block(r, show_baseline=True):
    audit = r["audit"]
    records = {x["log_id"]: x for x in r["records"] if x["record_type"] == "ACTION"}
    s = audit["summary"]
    base = r["baseline"]
    out = []
    if show_baseline:
        dmg = "".join(f"<li>{escape(d)}</li>" for d in base["damages"]) or "<li>피해 없음</li>"
        log = escape("\n".join(base["plain_log"]))
        harmful = [a for a in audit["actions"] if a["harmful"]]
        gov_items = []
        if s["prevented"]:
            gov_items.append(f"오작동 {s['prevented']}건 실행 전 차단")
        gov_items += [f"피해 발생: {escape(a['target'])} → {escape(a['attribution']['conclusion'])}" for a in harmful]
        if not gov_items:
            gov_items.append("오작동 없음, 정상 대응 완료")
        gov_items.append(f"자동 {s['auto']} · 실행 후 검토 {s['post_review']} · 사전 승인 {s['pre_approval']}")
        out.append(
            "<div class='cmp'>"
            f"<div class='box {'bad' if base['damages'] else ''}'><h4>통제 없음 (현행)</h4><ul>{dmg}</ul>"
            f"<p class='small muted'>남는 기록 (판단근거 없음)</p><pre>{log}</pre>"
            "<p class='small'>원인 규명·책임 판단: <b class='badtxt'>불가</b></p></div>"
            f"<div class='box {'bad' if harmful else 'ok'}'><h4>제안 체계 적용</h4><ul>"
            + "".join(f"<li>{g}</li>" for g in gov_items) + "</ul>"
            + _integrity(audit) + "<p class='small'>원인 규명·책임 판단: <b class='good'>가능</b> (아래 상세)</p></div>"
            "</div>")
    out.append("<div class='scroll'><table><tr><th>행동</th><th>대상</th><th>신뢰도</th><th>위험도</th>"
               "<th>개입 방식</th><th>승인</th><th>실행</th><th>사후 판정</th><th>보안 경고</th></tr>"
               + "".join(_action_row(a) for a in audit["actions"]) + "</table></div>")
    for a in audit["actions"]:
        out.append(f"<details><summary>{escape(a['log_id'])} · {escape(ACTION_KO.get(a['action_type'], ''))} "
                   f"상세 (설명가능성 로그 재구성)</summary><div>{_action_detail(a, records.get(a['log_id']))}</div></details>")
    return "".join(out)


def _matrix(results, faults):
    by = {(r["scenario"]["key"], r["fault"]): r for r in results}
    keys = []
    for r in results:
        if r["scenario"]["key"] not in [k for k, _ in keys]:
            keys.append((r["scenario"]["key"], r["scenario"]["title"]))
    head = "".join(f"<th>{escape(FAULT_KO[f])}</th>" for f in faults)
    rows = []
    for key, title in keys:
        cells = []
        for f in faults:
            r = by.get((key, f))
            if not r:
                cells.append("<td>-</td>")
                continue
            s = r["audit"]["summary"]
            if s["harmful"]:
                parties = ", ".join(r["audit"]["summary"]["responsible_parties"]) or "면책·감경"
                cells.append(f"<td><span class='badtxt'>피해 {s['harmful']}건</span><br>책임: <b>{escape(parties)}</b></td>")
            elif s["prevented"]:
                cells.append(f"<td><span class='good'>사전 차단 {s['prevented']}건</span>"
                             + (f"<br><span class='small warntxt'>지적 {s['findings']}건</span>" if s["findings"] else "")
                             + "</td>")
            else:
                cells.append("<td><span class='good'>정상 대응</span>"
                             + (f"<br><span class='small warntxt'>지적 {s['findings']}건</span>" if s["findings"] else "")
                             + "</td>")
        rows.append(f"<tr><td><b>{escape(title)}</b></td>{''.join(cells)}</tr>")
    return f"<div class='scroll'><table><tr><th>시나리오</th>{head}</tr>{''.join(rows)}</table></div>"


def build_report(results: list, path) -> Path:
    faults = []
    for r in results:
        if r["fault"] not in faults:
            faults.append(r["fault"])
    primary = [r for r in results if r["fault"] == faults[0]]
    base_dmg = sum(len(r["baseline"]["damages"]) for r in primary)
    gov_harm = sum(r["audit"]["summary"]["harmful"] for r in primary)
    prevented = sum(r["audit"]["summary"]["prevented"] for r in primary)
    decisions = sum(r["audit"]["summary"]["actions"] for r in primary)
    intact = all(r["audit"]["integrity"]["chain_ok"] and r["audit"]["integrity"]["anchor_ok"] for r in results)

    body = [
        "<h1>XAI-Guard 검증 결과 보고서</h1>",
        "<p class='muted'>자율형 AI 보안대응의 설명가능성 확보 및 책임귀속 체계 — 검증 프로토타입 · "
        f"생성 {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>",
        "<div class='kpis'>",
        f"<div class='kpi'><span class='muted small'>AI 자율 대응 결정</span><b>{decisions}건</b></div>",
        f"<div class='kpi'><span class='muted small'>현행 방식 피해</span><b class='badtxt'>{base_dmg}건</b></div>",
        f"<div class='kpi'><span class='muted small'>제안 체계 피해 ({escape(FAULT_KO[faults[0]])})</span>"
        f"<b class='{'badtxt' if gov_harm else 'good'}'>{gov_harm}건</b></div>",
        f"<div class='kpi'><span class='muted small'>실행 전 차단된 오작동</span><b class='good'>{prevented}건</b></div>",
        f"<div class='kpi'><span class='muted small'>로그 무결성</span><b class='{'good' if intact else 'badtxt'}'>"
        f"{'정상' if intact else '손상 탐지'}</b></div>",
        "</div>",
    ]
    if len(faults) > 1:
        body.append("<h2>책임귀속 매트릭스</h2><p class='muted small'>같은 시나리오에서 어느 주체가 의무를 "
                    "위반했는지에 따라 피해 발생 여부와 책임 주체가 달라진다. 감사 검증기는 원장 기록만으로 이를 판정한다.</p>")
        body.append(_matrix(results, faults))

    body.append(f"<h2>시나리오별 결과 — {escape(FAULT_KO[faults[0]])}</h2>")
    for r in primary:
        sc = r["scenario"]
        body.append(f"<section class='card'><h3>{escape(sc['title'])}</h3>"
                    f"<p class='muted small'>{escape(sc['description'])} · 사건번호 {escape(sc['incident_id'])}</p>"
                    + _run_block(r) + "</section>")

    for f in faults[1:]:
        body.append(f"<h2>과실 시연 — {escape(FAULT_KO[f])}</h2>")
        for r in results:
            if r["fault"] == f:
                body.append(f"<details><summary>{escape(r['scenario']['title'])} · "
                            f"피해 {r['audit']['summary']['harmful']}건 · 지적 {r['audit']['summary']['findings']}건"
                            f"</summary><div>{_run_block(r, show_baseline=False)}{_integrity(r['audit'])}</div></details>")

    html = ("<!doctype html><html lang='ko'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>XAI-Guard 검증 보고서</title><style>{CSS}</style></head><body><main>"
            + "".join(body) + "</main></body></html>")
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")
    return path
