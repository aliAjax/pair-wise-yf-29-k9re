import base64
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path

from app import BusinessError, CustodyStore


class CustodyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = CustodyStore(Path(self.tmp.name) / "test.db")
        self.store.seed()
        self.case = self.store.create_case("custodian1", "CASE-2026-001", "跨境资金调查")
        self.store.add_member("custodian1", self.case["id"], "custodian2", "custodian")
        self.store.add_member("custodian1", self.case["id"], "analyst1", "analyst")
        self.store.add_member("custodian1", self.case["id"], "auditor1", "auditor")
        self.retention = (date.today() + timedelta(days=3650)).isoformat()

    def tearDown(self):
        self.tmp.cleanup()

    def test_full_custody_analysis_release_and_integrity_report(self):
        raw = b"bank statement original bytes"
        item = self.store.ingest_evidence(
            "custodian1", self.case["id"], "E-001", "statement.csv",
            base64.b64encode(raw).decode(), self.retention, "custodian1",
        )
        opened = self.store.open_evidence("custodian1", item["id"], "A 区证物室", "两名人员在场开箱")
        self.assertEqual(opened["status"], "opened")
        child = self.store.derive(
            "analyst1", item["id"], "CSV 提取交易记录", "E-001-D1", "transactions.json",
            base64.b64encode(b'[{"amount": 100}]').decode(),
        )
        self.store.transfer("custodian2", item["id"], "custodian2", "法院证物库", "封存后移交")
        self.store.release("custodian2", item["id"], "检察机关", "按调取令释放原件")
        report = self.store.report("auditor1", self.case["id"])
        self.assertTrue(report["overall_integrity_valid"])
        self.assertEqual(report["evidence_count"], 2)
        original = next(x for x in report["evidence"] if x["id"] == item["id"])
        self.assertEqual(original["status"], "released")
        self.assertTrue(original["chain_valid"])
        self.assertEqual(child["parent_id"], item["id"])

    def test_permissions_and_legal_hold_block_release(self):
        item = self.store.ingest_evidence(
            "custodian1", self.case["id"], "E-002", "raw.bin",
            base64.b64encode(b"evidence").decode(), self.retention,
        )
        with self.assertRaises(BusinessError) as ctx:
            self.store.get_evidence("outsider", item["id"])
        self.assertEqual(ctx.exception.status, 403)
        with self.assertRaises(BusinessError) as ctx:
            self.store.release("analyst1", item["id"], "外部机构")
        self.assertEqual(ctx.exception.status, 403)
        self.store.set_hold("auditor1", item["id"], True, "诉讼保全要求")
        with self.assertRaises(BusinessError) as ctx:
            self.store.release("custodian1", item["id"], "外部机构")
        self.assertEqual(ctx.exception.code, "legal_hold_active")

    def test_cross_case_reuse_custody_number_location_and_chain(self):
        raw = b"shared content across two cases"
        first = self.store.ingest_evidence(
            "custodian1", self.case["id"], "E-101", "shared.bin",
            base64.b64encode(raw).decode(), self.retention, "custodian1",
        )
        # 同一份内容被别的案件再次入册 -> 复用原保管号、位置和事件链
        second_case = self.store.create_case("custodian1", "CASE-2026-002", "跨案复用案件")
        self.store.add_member("custodian1", second_case["id"], "custodian2", "custodian")
        second = self.store.ingest_evidence(
            "custodian2", second_case["id"], "E-201", "shared.bin",
            base64.b64encode(raw).decode(), self.retention, "custodian2",
        )
        self.assertEqual(second["id"], first["id"])
        self.assertTrue(second["reused"])
        self.assertEqual(second["current_custodian"], first["current_custodian"])
        ev1 = self.store.get_evidence("custodian1", first["id"], case_id=self.case["id"])
        ev2 = self.store.get_evidence("custodian2", second["id"], case_id=second_case["id"])
        self.assertEqual(len(ev1["events"]), len(ev2["events"]))
        # 各案件自己管释放：案件一放行不影响案件二
        self.store.release("custodian1", first["id"], "检察机关", "案件一放行", case_id=self.case["id"])
        ev1b = self.store.get_evidence("custodian1", first["id"], case_id=self.case["id"])
        ev2b = self.store.get_evidence("custodian2", second["id"], case_id=second_case["id"])
        self.assertEqual(ev1b["status"], "released")
        self.assertEqual(ev2b["status"], "custody")
        # 案件二放行也不影响案件一
        self.store.release("custodian2", first["id"], "检察机关", "案件二放行", case_id=second_case["id"])
        ev1c = self.store.get_evidence("custodian1", first["id"], case_id=self.case["id"])
        ev2c = self.store.get_evidence("custodian2", second["id"], case_id=second_case["id"])
        self.assertEqual(ev1c["status"], "released")
        self.assertEqual(ev2c["status"], "released")
        # 越权释放：非案件成员无权释放该案件的保留
        with self.assertRaises(BusinessError) as ctx:
            self.store.release("outsider", first["id"], "外部机构", case_id=self.case["id"])
        self.assertEqual(ctx.exception.status, 403)

    def test_archive_manifest_verification_replay_and_recompute(self):
        raw = b"archive verified content"
        item = self.store.ingest_evidence(
            "custodian1", self.case["id"], "E-301", "arch.bin",
            base64.b64encode(raw).decode(), self.retention, "custodian1",
        )
        # 按阶段送存封存清单
        m1 = self.store.submit_manifest("custodian1", self.case["id"], "MF-001", [
            {"evidence_id": item["id"], "sha256": item["sha256"], "label": "E-301"},
        ])
        self.assertEqual(m1["results"][0]["result"], "verified")
        # 同一清单并发提交只保存第一条（清单头幂等），但产生新批次
        m1b = self.store.submit_manifest("custodian1", self.case["id"], "MF-001", [
            {"sha256": "0" * 64, "label": "E-302"},
        ])
        self.assertEqual(m1b["manifest_id"], m1["manifest_id"])
        self.assertEqual(m1b["batch_number"], 2)
        # 缺件
        m2 = self.store.submit_manifest("custodian1", self.case["id"], "MF-002", [
            {"sha256": "0" * 64, "label": "MISSING"},
        ])
        self.assertEqual(m2["results"][0]["result"], "missing")
        # 损坏件（清单哈希与证据实际哈希不一致）
        m3 = self.store.submit_manifest("custodian1", self.case["id"], "MF-003", [
            {"evidence_id": item["id"], "sha256": "f" * 64, "label": "E-301-damaged"},
        ])
        self.assertEqual(m3["results"][0]["result"], "damaged")
        # 中断失败后重放：把条目回退到 pending，重放补全
        with self.store.connect() as conn:
            conn.execute("UPDATE archive_item SET result='pending', reason='', processed_at=NULL WHERE manifest_id=?", (m1["manifest_id"],))
            conn.execute("UPDATE archive_batch SET status='failed', processed_at=NULL WHERE manifest_id=?", (m1["manifest_id"],))
        replay = self.store.replay_manifest("custodian1", m1["manifest_id"])
        self.assertGreaterEqual(replay["processed_count"], 1)
        man = self.store.get_manifest("auditor1", m1["manifest_id"])
        for it in man["items"]:
            self.assertNotEqual(it["result"], "pending")
        # 权威状态一变就作废重算：释放证据后清单条目标记为换出
        self.store.release("custodian1", item["id"], "检察机关", "放行", case_id=self.case["id"])
        man2 = self.store.get_manifest("auditor1", m1["manifest_id"])
        swapped = [it for it in man2["items"] if it["result"] == "swapped_out"]
        self.assertEqual(len(swapped), 1)
        # 原保管记录保持不动
        ev = self.store.get_evidence("custodian1", item["id"], case_id=self.case["id"])
        self.assertEqual(ev["status"], "released")
        # 报告包含重算结果
        rep = self.store.report("auditor1", self.case["id"])
        self.assertIn("archive", rep)
        self.assertGreaterEqual(len(rep["archive"]), 1)


if __name__ == "__main__":
    unittest.main()
