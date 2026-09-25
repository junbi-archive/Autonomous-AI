"""시나리오 실행기: '통제 없음(기존)'과 '제안 체계'를 같은 입력으로 비교한다."""

import shutil
from datetime import timedelta
from pathlib import Path

from . import auditor
from .agent import MockAutonomousAgent
from .approvers import CarefulOperator, InteractiveOperator, NegligentOperator
from .clock import SimClock
from .environment import Environment, describe_damage
from .evidence import EvidenceStore
from .gateway import HumanOversightGateway, VendorProfile
from .ledger import HashChainLedger
from .ncti import NctiClient
from .policy import Policy, load_inventory
from .scenarios import KNOWN_SESSIONS

AGENCY_ID = "GOV-DEMO-0001"
INVESTIGATOR = "합동조사반(사고조사)"
FAULTS = ("none", "vendor", "agency", "operator")


def run_baseline(scn) -> dict:
    """현행: AI가 결정 즉시 실행하고, '무엇을 했는지'만 남는다."""
    inventory = load_inventory()
    env = Environment(inventory)
    clock = SimClock(scn.start)
    actions, plain_log, damages = [], [], []
    for p in MockAutonomousAgent(inventory).analyze(scn.logs):
        effect = env.execute(p.action_type, p.target, p.parameters)
        verdict = scn.truth.get(p.action_type)
        plain_log.append(f"{clock.iso()} EXECUTED {p.action_type} {p.target}")
        actions.append({"action_type": p.action_type, "target": p.target, "effect": effect, "verdict": verdict})
        if verdict in auditor.HARMFUL_VERDICTS:
            damages.append(describe_damage(p.action_type, p.target, inventory))
        clock.advance(5)
    return {"actions": actions, "plain_log": plain_log, "damages": damages}


def _make_approver(fault: str, operator: str):
    if operator == "interactive":
        return InteractiveOperator(KNOWN_SESSIONS)
    if fault == "operator":
        return NegligentOperator()
    return CarefulOperator(KNOWN_SESSIONS)


def run_governed(scn, workdir, fault: str = "none", operator: str = "auto") -> dict:
    """제안 체계: 게이트웨이 + 설명가능성 로그 + 사후 감사."""
    workdir = Path(workdir)
    if workdir.exists():
        shutil.rmtree(workdir)
    inventory = load_inventory()
    clock = SimClock(scn.start)
    ledger = HashChainLedger(workdir / "ledger.jsonl")
    ncti = NctiClient(workdir / "ncti")
    approver = _make_approver(fault, operator)
    agent = MockAutonomousAgent(inventory)
    gateway = HumanOversightGateway(
        policy=Policy.agency_lax() if fault == "agency" else Policy.standard(),
        ledger=ledger,
        evidence_store=EvidenceStore(workdir / "evidence"),
        approver=approver,
        environment=Environment(inventory),
        clock=clock,
        agency_id=AGENCY_ID,
        system_info=agent.system_info,
        vendor=VendorProfile.faulty() if fault == "vendor" else VendorProfile(),
    )

    actions = [gateway.submit(scn.incident_id, p) for p in agent.analyze(scn.logs)]
    ncti.anchor(AGENCY_ID, ledger, clock.iso())

    for rec in actions:
        if rec["approval"]["status"] == "PENDING_REVIEW":
            clock.advance(2 * 3600)
            truth = scn.truth.get(rec["action"]["type"], "INCONCLUSIVE")
            verdict, remediation, comment = approver.post_review(rec, truth)
            gateway.post_review(rec, approver.approver_id, verdict, remediation, comment)

    clock.advance(24 * 3600)
    for rec in actions:
        truth = scn.truth.get(rec["action"]["type"], "INCONCLUSIVE")
        executed = rec["execution"]["status"] == "EXECUTED"
        remediation = "ROLLED_BACK" if executed and truth in auditor.HARMFUL_VERDICTS else "NONE"
        gateway.investigate(rec, INVESTIGATOR, truth, remediation, scn.investigation.get(truth, ""))
    ncti.anchor(AGENCY_ID, ledger, clock.iso())
    ncti.share_case(scn.incident_id, ledger.records(), clock.iso())

    result = auditor.audit(workdir)
    auditor.save_audit(result, workdir / "audit.json")
    return {"workdir": str(workdir), "fault": fault, "audit": result, "records": ledger.records()}


def run_all(scenarios, faults, out, operator="auto") -> list:
    out = Path(out)
    results = []
    for scn in scenarios:
        baseline = run_baseline(scn)
        for fault in faults:
            governed = run_governed(scn, out / fault / scn.key, fault, operator)
            results.append({
                "scenario": {"key": scn.key, "title": scn.title, "description": scn.description,
                             "incident_id": scn.incident_id},
                "baseline": baseline,
                **governed,
            })
    return results
