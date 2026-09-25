import tempfile
import unittest
from pathlib import Path

from xai_guard import auditor, detectors
from xai_guard.ledger import HashChainLedger, load_records, verify_chain
from xai_guard.policy import Policy
from xai_guard.runner import run_governed
from xai_guard.scenarios import INJECTED_UA, SCENARIOS
from xai_guard.schema import validate_record
from xai_guard.tamper import tamper


class LedgerTest(unittest.TestCase):
    def test_chain_detects_modification(self):
        with tempfile.TemporaryDirectory() as d:
            ledger = HashChainLedger(Path(d) / "l.jsonl")
            for i in range(3):
                ledger.append({"n": i})
            records = load_records(ledger.path)
            self.assertEqual(verify_chain(records), [])
            records[1]["n"] = 99
            codes = {i["code"] for i in verify_chain(records)}
            self.assertIn("HASH_MISMATCH", codes)

    def test_chain_detects_deletion(self):
        with tempfile.TemporaryDirectory() as d:
            ledger = HashChainLedger(Path(d) / "l.jsonl")
            for i in range(3):
                ledger.append({"n": i})
            records = load_records(ledger.path)
            del records[1]
            codes = {i["code"] for i in verify_chain(records)}
            self.assertIn("PREV_HASH_MISMATCH", codes)


class PolicyTest(unittest.TestCase):
    def setUp(self):
        self.p = Policy.standard()

    def test_tiers(self):
        self.assertEqual(self.p.assess("BLOCK_IP", "-", 0.95, []).mode, "AUTO")
        self.assertEqual(self.p.assess("QUARANTINE_FILE", "O", 0.93, []).mode, "POST_REVIEW")
        self.assertEqual(self.p.assess("ISOLATE_HOST", "O", 0.99, []).mode, "PRE_APPROVAL")
        self.assertEqual(self.p.assess("DISABLE_ACCOUNT", "C", 0.99, []).mode, "PRE_APPROVAL")

    def test_low_confidence_escalates(self):
        self.assertEqual(self.p.assess("BLOCK_IP", "-", 0.5, []).tier, 2)

    def test_high_flag_escalates(self):
        flag = [{"code": "INDIRECT_PROMPT_INJECTION", "severity": "HIGH"}]
        self.assertEqual(self.p.assess("BLOCK_IP", "-", 0.99, flag).tier, 3)


class DetectorTest(unittest.TestCase):
    def test_injection_detected(self):
        flags = detectors.injection_flags([("EV-1", INJECTED_UA)], "db-classified-01")
        codes = {f["code"] for f in flags}
        self.assertEqual(codes, {"INDIRECT_PROMPT_INJECTION", "TARGET_FROM_UNTRUSTED_TEXT"})

    def test_normal_logs_clean(self):
        for scn in SCENARIOS.values():
            if scn.key == "injection":
                continue
            for source, lines in scn.logs.items():
                self.assertEqual(detectors.injection_flags([(source, "\n".join(lines))]), [], source)


class ScenarioTest(unittest.TestCase):
    def run_case(self, key, fault):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        result = run_governed(SCENARIOS[key], Path(self.tmp.name) / key, fault)
        return result["audit"]

    def test_all_records_schema_valid(self):
        with tempfile.TemporaryDirectory() as d:
            for key, scn in SCENARIOS.items():
                res = run_governed(scn, Path(d) / key)
                for rec in res["records"]:
                    self.assertEqual(validate_record(rec), [], rec["log_id"])

    def test_standard_operation_prevents_harm(self):
        for key in SCENARIOS:
            audit = self.run_case(key, "none")
            self.assertEqual(audit["summary"]["harmful"], 0, key)
            self.assertEqual(audit["summary"]["findings"], 0, key)
            self.assertTrue(audit["integrity"]["chain_ok"])
        self.assertEqual(self.run_case("fp", "none")["summary"]["prevented"], 1)
        self.assertEqual(self.run_case("injection", "none")["summary"]["prevented"], 1)

    def test_attribution(self):
        expected = {"vendor": "개발사", "agency": "도입기관", "operator": "운영자(승인자)"}
        for fault, party in expected.items():
            audit = self.run_case("injection", fault)
            self.assertEqual(audit["summary"]["harmful"], 1, fault)
            self.assertEqual(list(audit["summary"]["responsible_parties"]), [party], fault)

    def test_tamper_detection(self):
        with tempfile.TemporaryDirectory() as d:
            wd = Path(d) / "inj"
            run_governed(SCENARIOS["injection"], wd)
            tamper(wd, 2)
            self.assertFalse(auditor.audit(wd)["integrity"]["chain_ok"])
        with tempfile.TemporaryDirectory() as d:
            wd = Path(d) / "inj"
            run_governed(SCENARIOS["injection"], wd)
            tamper(wd, 2, recompute=True)
            integrity = auditor.audit(wd)["integrity"]
            self.assertTrue(integrity["chain_ok"])
            self.assertFalse(integrity["anchor_ok"])

    def test_evidence_tampering_detected(self):
        with tempfile.TemporaryDirectory() as d:
            wd = Path(d) / "inj"
            run_governed(SCENARIOS["injection"], wd)
            ev = next((wd / "evidence").glob("*.txt"))
            ev.write_text("수정된 로그", encoding="utf-8")
            codes = {f["code"] for a in auditor.audit(wd)["actions"] for f in a["findings"]}
            self.assertIn("EVIDENCE_INTEGRITY", codes)


if __name__ == "__main__":
    unittest.main()
