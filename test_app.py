import base64
import tempfile
import threading
import unittest
from datetime import date, timedelta
from pathlib import Path

from app import BusinessError, CustodyStore


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


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
            b64(raw), self.retention, "custodian1",
        )
        opened = self.store.open_evidence("custodian1", item["id"], "A 区证物室", "两名人员在场开箱")
        self.assertEqual(opened["status"], "opened")
        child = self.store.derive(
            "analyst1", item["id"], "CSV 提取交易记录", "E-001-D1", "transactions.json",
            b64(b'[{"amount": 100}]'),
        )
        self.store.transfer("custodian2", item["id"], "custodian2", "法院证物库", "封存后移交")
        self.store.release("custodian2", item["id"], "检察机关", "按调取令释放原件")
        report = self.store.report("auditor1", self.case["id"])
        self.assertTrue(report["overall_integrity_valid"])
        self.assertEqual(report["evidence_count"], 2)
        self.assertEqual(report["parent_child_links"][0]["parent_evidence_id"], item["id"])
        self.assertEqual(report["parent_child_links"][0]["child_evidence_id"], child["id"])
        original = next(x for x in report["evidence"] if x["id"] == item["id"])
        self.assertEqual(original["status"], "released")
        self.assertTrue(original["chain_valid"])
        self.assertEqual(child["parent_id"], item["id"])
        # 报告含归档重算区块
        self.assertIn("archive", report)
        self.assertEqual(report["archive"]["batch_count"], 0)

    def test_permissions_and_legal_hold_block_release(self):
        item = self.store.ingest_evidence(
            "custodian1", self.case["id"], "E-002", "raw.bin",
            b64(b"evidence"), self.retention,
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

    def test_cross_case_reuse_shares_number_location_and_chain(self):
        raw = b"cross case shared evidence payload"
        first = self.store.ingest_evidence(
            "custodian1", self.case["id"], "E-SHARED", "shared.bin",
            b64(raw), self.retention, "custodian1",
        )
        self.assertFalse(first["reused"])
        self.store.transfer("custodian1", first["id"], "custodian2", "中心证物库 3 号柜", "统一入库")
        # 第二个案件由另一拨人办理
        case2 = self.store.create_case("custodian2", "CASE-2026-002", "关联诈骗案")
        reused = self.store.ingest_evidence(
            "custodian2", case2["id"], "F-COPY", "shared.bin",
            b64(raw), self.retention, "custodian2",
        )
        self.assertTrue(reused["reused"])
        self.assertEqual(reused["custody_number"], first["custody_number"])
        self.assertEqual(reused["item_id"], first["item_id"])
        detail = self.store.get_evidence("custodian2", reused["id"])
        # 复用原保管位置和同一条事件链
        self.assertEqual(detail["shared_item"]["current_location"], "中心证物库 3 号柜")
        self.assertEqual(detail["shared_item"]["current_custodian"], "custodian2")
        event_types = [e["event_type"] for e in detail["events"]]
        self.assertEqual(event_types, ["INGEST", "TRANSFER", "CROSS_REUSE"])
        cross = detail["events"][-1]
        self.assertEqual(cross["case_id"], case2["id"])
        self.assertEqual(len(detail["shared_item"]["registrations"]), 2)

    def test_release_and_hold_are_isolated_per_case_and_cross_release_denied(self):
        raw = b"isolation evidence payload"
        first = self.store.ingest_evidence(
            "custodian1", self.case["id"], "E-ISO", "iso.bin", b64(raw), self.retention,
        )
        case2 = self.store.create_case("custodian2", "CASE-2026-003", "另一起关联案件")
        second = self.store.ingest_evidence(
            "custodian2", case2["id"], "F-ISO", "iso.bin", b64(raw), self.retention,
        )
        # 案件 1 的保管员不是案件 2 成员，越权释放必须被拒绝，且状态不变
        with self.assertRaises(BusinessError) as ctx:
            self.store.release("custodian1", second["id"], "外部机构")
        self.assertEqual(ctx.exception.status, 403)
        # 案件 1 设置法律保留，不影响案件 2 放行
        self.store.set_hold("custodian1", first["id"], True, "案件一仍在诉讼中")
        released = self.store.release("custodian2", second["id"], "案件二法院", "案件二审结放行")
        self.assertEqual(released["status"], "released")
        self.assertTrue(released["other_case_registrations_remain"])
        first_detail = self.store.get_evidence("custodian1", first["id"])
        self.assertEqual(first_detail["status"], "custody")
        self.assertTrue(first_detail["legal_hold"])
        # 共享链上有案件 2 的 RELEASE，但不归属案件 1（一个案件放行不影响另一个）
        release_events = [e for e in first_detail["events"] if e["event_type"] == "RELEASE"]
        self.assertEqual(len(release_events), 1)
        self.assertEqual(release_events[0]["case_id"], case2["id"])
        # 案件 2 放行后案件 1 仍因自己的法律保留无法放行
        with self.assertRaises(BusinessError) as ctx:
            self.store.release("custodian1", first["id"], "外部机构")
        self.assertEqual(ctx.exception.code, "legal_hold_active")
        # 案件 1 解除保留后可以放行；此时物证才物理出库
        self.store.set_hold("custodian1", first["id"], False, "诉讼终结解除保留")
        self.store.release("custodian1", first["id"], "案件一法院", "案件一放行")
        report2 = self.store.report("custodian2", case2["id"])
        row = report2["evidence"][0]
        self.assertEqual(row["status"], "released")
        self.assertEqual(row["physical_status"], "released")
        self.assertEqual(row["cross_case_reuse"]["other_registrations"][0]["status"], "released")

    def _one_item_manifest(self, number, location="", sha=""):
        return [{"custody_number": number, "expected_location": location, "expected_sha256": sha}]

    def test_archive_batch_verified_and_missing_and_report_marks_children(self):
        raw = b"archive manifest evidence"
        item = self.store.ingest_evidence(
            "custodian1", self.case["id"], "E-ARC", "arc.bin", b64(raw),
            self.retention, "custodian1",
        )
        self.store.add_member("custodian1", self.case["id"], "archive_mw", "auditor")
        batch = self.store.submit_manifest(
            "archive_mw", self.case["id"], "BATCH-STAGE-1", "stage-1-封存",
            self._one_item_manifest(item["custody_number"]),
        )
        self.assertEqual(batch["status"], "completed")
        self.assertEqual(batch["counts"]["verified"], 1)
        self.assertEqual(batch["entries"][0]["status"], "verified")
        self.assertTrue(batch["entries"][0]["reason"].startswith("保管号"))
        # 不存在的保管号：缺件
        batch2 = self.store.submit_manifest(
            "archive_mw", self.case["id"], "BATCH-STAGE-2", "stage-2-补录",
            self._one_item_manifest("EV-999999"),
        )
        self.assertEqual(batch2["entries"][0]["status"], "missing")
        self.assertIn("缺件", batch2["entries"][0]["reason"])
        report = self.store.report("auditor1", self.case["id"])
        self.assertEqual(report["archive"]["batch_count"], 2)
        self.assertEqual(report["archive"]["missing_total"], 1)

    def test_duplicate_manifest_keeps_first_concurrent_submission(self):
        raw = b"duplicate manifest evidence"
        item = self.store.ingest_evidence(
            "custodian1", self.case["id"], "E-DUP", "dup.bin", b64(raw), self.retention,
        )
        self.store.add_member("custodian1", self.case["id"], "archive_mw", "auditor")
        entries = self._one_item_manifest(item["custody_number"])
        results, errors = [], []

        def submit():
            try:
                results.append(self.store.submit_manifest(
                    "archive_mw", self.case["id"], "BATCH-ONCE", "stage-1", entries,
                ))
            except Exception as exc:  # pragma: no cover - 并发串行化后不应发生
                errors.append(exc)

        threads = [threading.Thread(target=submit) for _ in range(4)]
        for t in threads: t.start()
        for t in threads: t.join()
        self.assertFalse(errors)
        self.assertEqual(len(results), 4)
        self.assertEqual({r["id"] for r in results}, {results[0]["id"]})
        self.assertEqual(sum(1 for r in results if r.get("duplicate")), 3)
        listing = self.store.list_batches("auditor1", self.case["id"])
        self.assertEqual(listing["batch_count"], 1)
        self.assertEqual(listing["batches"][0]["batch_number"], "BATCH-ONCE")

    def test_interrupted_batch_replay_completes_remaining_entries(self):
        numbers = []
        for i in range(4):
            ev = self.store.ingest_evidence(
                "custodian1", self.case["id"], f"E-INT{i}", f"f{i}.bin",
                b64(f"interrupt payload {i}".encode()), self.retention,
            )
            numbers.append(ev["custody_number"])
        self.store.add_member("custodian1", self.case["id"], "archive_mw", "auditor")
        # 提交后只处理 2 条，模拟中间件分阶段送达 / 中断
        batch = self.store.submit_manifest(
            "archive_mw", self.case["id"], "BATCH-CHUNK", "stage-1",
            [{"custody_number": n} for n in numbers], initial_limit=2,
        )
        self.assertEqual(batch["status"], "processing")
        self.assertEqual(batch["counts"]["verified"], 2)
        self.assertEqual(batch["counts"]["pending"], 2)
        partial = batch
        # 单条处理失败：前面已提交的进度保留，失败条及之后保持待处理
        original = self.store._evaluate_entry

        def flaky(conn, case_id, entry):
            if entry["custody_number"] == numbers[2]:
                raise RuntimeError("中间件连接中断")
            return original(conn, case_id, entry)

        self.store._evaluate_entry = flaky
        with self.assertRaises(RuntimeError):
            self.store.process_batch("archive_mw", batch["id"])
        self.store._evaluate_entry = original
        failed = self.store.get_batch("archive_mw", batch["id"], refresh=False)
        self.assertEqual(failed["counts"]["verified"], 2)
        self.assertEqual(failed["counts"]["pending"], 2)
        # 重放：补全还没处理的记录，原保管记录不动
        replayed = self.store.replay_batch("archive_mw", "BATCH-CHUNK")
        self.assertEqual(replayed["status"], "completed")
        self.assertEqual(replayed["counts"]["verified"], 4)
        self.assertEqual(replayed["counts"]["pending"], 0)

    def test_drift_invalidates_result_and_marks_damaged_and_swapped(self):
        good = b"drift test content"
        item = self.store.ingest_evidence(
            "custodian1", self.case["id"], "E-DRIFT", "drift.bin", b64(good),
            self.retention, "custodian1",
        )
        damaged = self.store.ingest_evidence(
            "custodian1", self.case["id"], "E-DAMAGE", "damage.bin", b64(b"will be corrupted"),
            self.retention, "custodian1",
        )
        swapped = self.store.ingest_evidence(
            "custodian1", self.case["id"], "E-SWAP", "swap.bin", b64(b"will be released"),
            self.retention, "custodian1",
        )
        self.store.add_member("custodian1", self.case["id"], "archive_mw", "auditor")
        # 先把实物移交到清单声明的封存位置，初次核验全部通过
        self.store.transfer("custodian1", item["id"], "custodian2", "A 区证物室", "归档前入库")
        batch = self.store.submit_manifest(
            "archive_mw", self.case["id"], "BATCH-DRIFT", "stage-1",
            [
                {"custody_number": item["custody_number"], "expected_location": "A 区证物室"},
                {"custody_number": damaged["custody_number"]},
                {"custody_number": swapped["custody_number"]},
            ],
        )
        self.assertEqual(batch["counts"]["verified"], 3)
        # 权威状态变化 1：位置被移交走 → 指纹漂移，作废重算为换出
        self.store.transfer("custodian1", item["id"], "custodian2", "异地仓库", "调度出库")
        # 权威状态变化 2：本案件放行 → 换出记录
        self.store.release("custodian1", swapped["id"], "调取法院", "依法调取")
        # 权威状态变化 3：存储层内容被外部破坏（非本系统写入）→ 损坏件
        with self.store.connect() as conn:
            conn.execute(
                "UPDATE custody_items SET content=? WHERE custody_number=?",
                (b"corrupted bytes", damaged["custody_number"]),
            )
            conn.commit()
        refreshed = self.store.get_batch("archive_mw", batch["id"])
        statuses = {e["custody_number"]: e["status"] for e in refreshed["entries"]}
        self.assertEqual(statuses[item["custody_number"]], "swapped_out")
        self.assertEqual(statuses[damaged["custody_number"]], "damaged")
        self.assertEqual(statuses[swapped["custody_number"]], "swapped_out")
        self.assertGreaterEqual(refreshed["recompute_count"], 1)
        for entry in refreshed["entries"]:
            self.assertEqual(entry["previous_status"], "verified")
            self.assertGreaterEqual(entry["recompute_count"], 1)
        # 再次查看，状态未变，不重复重算
        again = self.store.get_batch("archive_mw", batch["id"])
        self.assertEqual(again["recompute_count"], refreshed["recompute_count"])
        # 原始保管事件链未被归档流程改动
        detail = self.store.get_evidence("custodian1", item["id"])
        self.assertEqual([e["event_type"] for e in detail["events"]],
                         ["INGEST", "TRANSFER", "TRANSFER"])
        report = self.store.report("auditor1", self.case["id"])
        self.assertEqual(report["archive"]["damaged_total"], 1)
        self.assertEqual(report["archive"]["swapped_out_total"], 2)


if __name__ == "__main__":
    unittest.main()
