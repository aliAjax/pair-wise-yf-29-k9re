"""法律证据保管与流转后台。"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import sqlite3
import threading
from datetime import date, datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB = BASE_DIR / "custody.db"
MEMBER_ROLES = {"custodian", "analyst", "auditor"}


class BusinessError(Exception):
    def __init__(self, message, status=400, code="bad_request"):
        super().__init__(message)
        self.message, self.status, self.code = message, status, code


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class CustodyStore:
    def __init__(self, db_path=DEFAULT_DB):
        self.db_path = str(db_path)
        self._lock = threading.Lock()

    def connect(self):
        conn = sqlite3.connect(self.db_path, timeout=15)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=15000")
        return conn

    def init_schema(self):
        with self._lock, self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS users(
                    id TEXT PRIMARY KEY, name TEXT NOT NULL,
                    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1))
                );
                CREATE TABLE IF NOT EXISTS cases(
                    id INTEGER PRIMARY KEY AUTOINCREMENT, case_number TEXT NOT NULL UNIQUE,
                    title TEXT NOT NULL, created_by TEXT NOT NULL REFERENCES users(id), created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS case_members(
                    case_id INTEGER NOT NULL REFERENCES cases(id), user_id TEXT NOT NULL REFERENCES users(id),
                    role TEXT NOT NULL CHECK(role IN ('custodian','analyst','auditor')),
                    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
                    granted_by TEXT NOT NULL REFERENCES users(id), granted_at TEXT NOT NULL,
                    PRIMARY KEY(case_id,user_id)
                );
                -- 共享保管记录：按内容 SHA-256 去重，跨案件复用保管号、位置与事件链
                CREATE TABLE IF NOT EXISTS evidence(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    filename TEXT NOT NULL, sha256 TEXT NOT NULL UNIQUE, size INTEGER NOT NULL,
                    content BLOB NOT NULL, current_custodian TEXT NOT NULL,
                    created_by TEXT NOT NULL REFERENCES users(id), created_at TEXT NOT NULL
                );
                -- 各案件入册记录：状态、法律保留、保留期限按案件独立管理
                CREATE TABLE IF NOT EXISTS case_evidence(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER NOT NULL REFERENCES cases(id),
                    evidence_id INTEGER NOT NULL REFERENCES evidence(id),
                    label TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'custody'
                        CHECK(status IN ('custody','opened','released','derivative')),
                    legal_hold INTEGER NOT NULL DEFAULT 0 CHECK(legal_hold IN (0,1)),
                    retention_until TEXT NOT NULL,
                    created_by TEXT NOT NULL REFERENCES users(id), created_at TEXT NOT NULL,
                    UNIQUE(case_id,label), UNIQUE(case_id,evidence_id)
                );
                CREATE TABLE IF NOT EXISTS custody_events(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    evidence_id INTEGER NOT NULL REFERENCES evidence(id), sequence INTEGER NOT NULL,
                    event_type TEXT NOT NULL CHECK(event_type IN ('INGEST','TRANSFER','OPEN','ANALYZE','RELEASE','HOLD_SET','HOLD_CLEARED')),
                    actor_id TEXT NOT NULL REFERENCES users(id), from_person TEXT,
                    to_person TEXT, location TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '',
                    previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL, UNIQUE(evidence_id,sequence)
                );
                CREATE TABLE IF NOT EXISTS derivatives(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    parent_evidence_id INTEGER NOT NULL REFERENCES evidence(id),
                    child_evidence_id INTEGER NOT NULL UNIQUE REFERENCES evidence(id),
                    method TEXT NOT NULL, actor_id TEXT NOT NULL REFERENCES users(id),
                    created_at TEXT NOT NULL, UNIQUE(parent_evidence_id,child_evidence_id)
                );
                CREATE TABLE IF NOT EXISTS audit_log(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER NOT NULL REFERENCES cases(id), actor_id TEXT NOT NULL REFERENCES users(id),
                    action TEXT NOT NULL, detail TEXT NOT NULL, created_at TEXT NOT NULL
                );
                -- 归档封存清单：按阶段（批次）送存，清单头幂等，条目按 SHA-256 去重
                CREATE TABLE IF NOT EXISTS archive_manifest(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    manifest_number TEXT NOT NULL UNIQUE,
                    case_id INTEGER NOT NULL REFERENCES cases(id),
                    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','void')),
                    state_hash TEXT NOT NULL DEFAULT '',
                    created_by TEXT NOT NULL REFERENCES users(id), created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS archive_batch(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    manifest_id INTEGER NOT NULL REFERENCES archive_manifest(id),
                    batch_number INTEGER NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','processing','completed','failed')),
                    created_at TEXT NOT NULL, processed_at TEXT,
                    UNIQUE(manifest_id,batch_number)
                );
                CREATE TABLE IF NOT EXISTS archive_item(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    batch_id INTEGER NOT NULL REFERENCES archive_batch(id),
                    manifest_id INTEGER NOT NULL REFERENCES archive_manifest(id),
                    evidence_id INTEGER REFERENCES evidence(id),
                    sha256 TEXT NOT NULL, label TEXT NOT NULL DEFAULT '',
                    result TEXT NOT NULL DEFAULT 'pending'
                        CHECK(result IN ('pending','verified','missing','damaged','swapped_out')),
                    reason TEXT NOT NULL DEFAULT '', processed_at TEXT,
                    UNIQUE(manifest_id,sha256)
                );
                """
            )

    def seed(self):
        self.init_schema()
        with self.connect() as conn:
            conn.executemany(
                "INSERT OR IGNORE INTO users(id,name) VALUES(?,?)",
                [
                    ("custodian1", "证据保管员甲"), ("custodian2", "证据保管员乙"),
                    ("analyst1", "电子数据分析员"), ("auditor1", "案件审计员"), ("outsider", "外部人员"),
                ],
            )

    def _user(self, conn, user_id):
        if not user_id:
            raise BusinessError("缺少 X-User-Id", 401, "authentication_required")
        user = conn.execute("SELECT * FROM users WHERE id=? AND active=1", (user_id,)).fetchone()
        if not user:
            raise BusinessError("用户不存在或已停用", 401, "unknown_user")
        return user

    def _case(self, conn, case_id):
        row = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        if not row:
            raise BusinessError("案件不存在", 404, "not_found")
        return row

    def _member(self, conn, case_id, user_id, roles=None):
        user = self._user(conn, user_id)
        self._case(conn, case_id)
        row = conn.execute(
            "SELECT * FROM case_members WHERE case_id=? AND user_id=? AND active=1", (case_id, user_id)
        ).fetchone()
        if not row:
            raise BusinessError("不是案件有效成员", 403, "forbidden")
        if roles and row["role"] not in roles:
            raise BusinessError("当前案件角色无权执行此操作", 403, "forbidden")
        return user, row

    def _audit(self, conn, case_id, actor_id, action, detail):
        conn.execute(
            "INSERT INTO audit_log(case_id,actor_id,action,detail,created_at) VALUES(?,?,?,?,?)",
            (case_id, actor_id, action, json.dumps(detail, ensure_ascii=False, sort_keys=True), now()),
        )

    def create_case(self, user_id, case_number, title):
        if not case_number.strip() or len(title.strip()) < 2:
            raise BusinessError("案件编号和标题不能为空", 422, "invalid_case")
        with self.connect() as conn:
            self._user(conn, user_id)
            try:
                cur = conn.execute(
                    "INSERT INTO cases(case_number,title,created_by,created_at) VALUES(?,?,?,?)",
                    (case_number.strip(), title.strip(), user_id, now()),
                )
            except sqlite3.IntegrityError:
                raise BusinessError("案件编号已存在", 409, "case_exists")
            case_id = cur.lastrowid
            conn.execute(
                "INSERT INTO case_members(case_id,user_id,role,granted_by,granted_at) VALUES(?,?,?,?,?)",
                (case_id, user_id, "custodian", user_id, now()),
            )
            self._audit(conn, case_id, user_id, "case.create", {"case_number": case_number.strip()})
            return {"id": case_id, "case_number": case_number.strip(), "title": title.strip()}

    def add_member(self, user_id, case_id, member_id, role):
        if role not in MEMBER_ROLES:
            raise BusinessError("案件角色必须是 custodian、analyst 或 auditor", 422, "invalid_role")
        with self.connect() as conn:
            case = self._case(conn, case_id)
            if case["created_by"] != user_id:
                raise BusinessError("只有案件创建人可以授权成员", 403, "forbidden")
            self._user(conn, member_id)
            conn.execute(
                """INSERT INTO case_members(case_id,user_id,role,active,granted_by,granted_at) VALUES(?,?,?,1,?,?)
                   ON CONFLICT(case_id,user_id) DO UPDATE SET role=excluded.role,active=1,granted_by=excluded.granted_by,granted_at=excluded.granted_at""",
                (case_id, member_id, role, user_id, now()),
            )
            self._audit(conn, case_id, user_id, "member.grant", {"member_id": member_id, "role": role})
            return {"case_id": case_id, "member_id": member_id, "role": role}

    @staticmethod
    def _event_hash(event):
        canonical = json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(canonical).hexdigest()

    def _append_event(self, conn, evidence_id, event_type, actor, from_person="", to_person="", location="", note=""):
        previous = conn.execute(
            "SELECT event_hash,sequence FROM custody_events WHERE evidence_id=? ORDER BY sequence DESC LIMIT 1", (evidence_id,)
        ).fetchone()
        sequence = (previous["sequence"] + 1) if previous else 1
        previous_hash = previous["event_hash"] if previous else "GENESIS"
        payload = {
            "evidence_id": evidence_id, "sequence": sequence, "event_type": event_type,
            "actor_id": actor, "from_person": from_person or None, "to_person": to_person or None,
            "location": location, "note": note, "previous_hash": previous_hash, "created_at": now(),
        }
        digest = self._event_hash(payload)
        cur = conn.execute(
            """INSERT INTO custody_events(evidence_id,sequence,event_type,actor_id,from_person,to_person,location,note,previous_hash,event_hash,created_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (evidence_id, sequence, event_type, actor, from_person or None, to_person or None, location, note, previous_hash, digest, payload["created_at"]),
        )
        return cur.lastrowid, digest

    def _resolve_case_evidence(self, conn, evidence_id, user_id, roles=None, case_id=None):
        """定位证据在某案件的入册记录。

        共享证据可被多个案件入册；未显式指定 case_id 时，依据用户在各案件的
        成员身份解析唯一的入册记录，避免越权操作其他案件的释放/保留。
        """
        self._evidence(conn, evidence_id)
        if case_id is not None:
            ce = conn.execute(
                "SELECT * FROM case_evidence WHERE case_id=? AND evidence_id=?", (case_id, evidence_id)
            ).fetchone()
            if not ce:
                raise BusinessError("该案件未入册此证据", 404, "not_found")
            self._member(conn, case_id, user_id, roles)
            return ce
        rows = conn.execute(
            """SELECT ce.*, cm.role AS member_role FROM case_evidence ce
               JOIN case_members cm ON cm.case_id=ce.case_id AND cm.active=1
               WHERE ce.evidence_id=? AND cm.user_id=?""",
            (evidence_id, user_id),
        ).fetchall()
        if roles:
            rows = [r for r in rows if r["member_role"] in roles]
        if not rows:
            raise BusinessError("不是案件有效成员或无权操作此证据", 403, "forbidden")
        if len(rows) > 1:
            raise BusinessError("用户属于多个入册此证据的案件，请指定 case_id", 409, "ambiguous_case")
        return rows[0]

    def ingest_evidence(self, user_id, case_id, label, filename, content_b64, retention_until, custodian=None):
        label, filename = label.strip(), filename.strip()
        if not label or not filename:
            raise BusinessError("证据标签和文件名不能为空", 422, "invalid_evidence")
        try:
            content = base64.b64decode(content_b64, validate=True)
            deadline = date.fromisoformat(retention_until)
        except (binascii.Error, ValueError, TypeError):
            raise BusinessError("证据内容 Base64 或保留期限格式错误", 422, "invalid_evidence")
        if deadline < date.today():
            raise BusinessError("保留期限不能早于今天", 422, "invalid_retention")
        digest = hashlib.sha256(content).hexdigest()
        custodian = (custodian or user_id).strip()
        with self.connect() as conn:
            _, member = self._member(conn, case_id, user_id, {"custodian"})
            if not custodian:
                raise BusinessError("保管人不能为空", 422, "invalid_custodian")
            try:
                conn.execute("BEGIN IMMEDIATE")
                existing = conn.execute("SELECT * FROM evidence WHERE sha256=?", (digest,)).fetchone()
                if existing:
                    # 跨案件复用：同一内容复用原保管号、位置与事件链
                    evidence_id = existing["id"]
                    dup = conn.execute(
                        "SELECT 1 FROM case_evidence WHERE case_id=? AND evidence_id=?", (case_id, evidence_id)
                    ).fetchone()
                    if dup:
                        raise BusinessError("该案件已入册同一证据", 409, "already_ingested")
                    conn.execute(
                        """INSERT INTO case_evidence(case_id,evidence_id,label,status,legal_hold,retention_until,created_by,created_at)
                           VALUES(?,?,?, 'custody',0,?,?,?)""",
                        (case_id, evidence_id, label, retention_until, user_id, now()),
                    )
                    self._audit(conn, case_id, user_id, "evidence.reuse", {"evidence_id": evidence_id, "sha256": digest, "label": label})
                    return {
                        "id": evidence_id, "label": label, "sha256": digest, "size": len(content),
                        "status": "custody", "current_custodian": existing["current_custodian"], "reused": True,
                    }
                cur = conn.execute(
                    """INSERT INTO evidence(filename,sha256,size,content,current_custodian,created_by,created_at)
                       VALUES(?,?,?,?,?,?,?)""",
                    (filename, digest, len(content), content, custodian, user_id, now()),
                )
                evidence_id = cur.lastrowid
                conn.execute(
                    """INSERT INTO case_evidence(case_id,evidence_id,label,status,legal_hold,retention_until,created_by,created_at)
                       VALUES(?,?,?, 'custody',0,?,?,?)""",
                    (case_id, evidence_id, label, retention_until, user_id, now()),
                )
                self._append_event(conn, evidence_id, "INGEST", user_id, to_person=custodian, note=f"入册 SHA-256 {digest}")
                self._audit(conn, case_id, user_id, "evidence.ingest", {"evidence_id": evidence_id, "sha256": digest, "label": label})
                return {"id": evidence_id, "label": label, "sha256": digest, "size": len(content), "status": "custody", "current_custodian": custodian, "reused": False}
            except sqlite3.IntegrityError:
                conn.rollback()
                raise BusinessError("该案件中的证据标签已存在", 409, "label_exists")
            except Exception:
                conn.rollback()
                raise

    def _evidence(self, conn, evidence_id):
        row = conn.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()
        if not row:
            raise BusinessError("证据不存在", 404, "not_found")
        return row

    def get_evidence(self, user_id, evidence_id, include_content=False, case_id=None):
        with self.connect() as conn:
            row = self._evidence(conn, evidence_id)
            ce = self._resolve_case_evidence(conn, evidence_id, user_id, case_id=case_id)
            result = {k: row[k] for k in row.keys() if k != "content"}
            result["case_id"] = ce["case_id"]
            result["label"] = ce["label"]
            result["status"] = ce["status"]
            result["legal_hold"] = bool(ce["legal_hold"])
            result["retention_until"] = ce["retention_until"]
            result["integrity_valid"] = hashlib.sha256(row["content"]).hexdigest() == row["sha256"]
            result["events"] = [dict(x) for x in conn.execute("SELECT * FROM custody_events WHERE evidence_id=? ORDER BY sequence", (evidence_id,)).fetchall()]
            result["derived_children"] = [dict(x) for x in conn.execute("SELECT * FROM derivatives WHERE parent_evidence_id=? ORDER BY id", (evidence_id,)).fetchall()]
            if include_content:
                result["content_b64"] = base64.b64encode(row["content"]).decode()
            return result

    def transfer(self, user_id, evidence_id, to_person, location, note="", case_id=None):
        if not to_person.strip() or not location.strip():
            raise BusinessError("接收人和保管位置不能为空", 422, "invalid_transfer")
        with self.connect() as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                row = self._evidence(conn, evidence_id)
                ce = self._resolve_case_evidence(conn, evidence_id, user_id, {"custodian"}, case_id)
                if ce["status"] == "released":
                    raise BusinessError("已释放证据不能再移交", 409, "evidence_released")
                self._append_event(conn, evidence_id, "TRANSFER", user_id, from_person=row["current_custodian"], to_person=to_person.strip(), location=location.strip(), note=note.strip())
                conn.execute("UPDATE evidence SET current_custodian=? WHERE id=?", (to_person.strip(), evidence_id))
                self._audit(conn, ce["case_id"], user_id, "custody.transfer", {"evidence_id": evidence_id, "to": to_person.strip(), "location": location.strip()})
                return {"id": evidence_id, "current_custodian": to_person.strip(), "location": location.strip()}
            except Exception:
                conn.rollback()
                raise

    def open_evidence(self, user_id, evidence_id, location, note="", case_id=None):
        if not location.strip():
            raise BusinessError("开箱地点不能为空", 422, "location_required")
        with self.connect() as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                row = self._evidence(conn, evidence_id)
                ce = self._resolve_case_evidence(conn, evidence_id, user_id, {"custodian"}, case_id)
                if ce["status"] != "custody":
                    raise BusinessError("只有处于封存保管状态的证据可以开箱", 409, "invalid_status")
                self._append_event(conn, evidence_id, "OPEN", user_id, from_person=row["current_custodian"], location=location.strip(), note=note.strip())
                conn.execute("UPDATE case_evidence SET status='opened' WHERE id=?", (ce["id"],))
                self._audit(conn, ce["case_id"], user_id, "evidence.open", {"evidence_id": evidence_id, "location": location.strip()})
                return {"id": evidence_id, "status": "opened", "location": location.strip()}
            except Exception:
                conn.rollback()
                raise

    def derive(self, user_id, evidence_id, method, label, filename, content_b64, case_id=None):
        if len(method.strip()) < 3 or not label.strip() or not filename.strip():
            raise BusinessError("分析方法、子证据标签和文件名不能为空", 422, "invalid_derivative")
        try:
            content = base64.b64decode(content_b64, validate=True)
        except (binascii.Error, ValueError, TypeError):
            raise BusinessError("content_b64 不是合法 Base64", 422, "invalid_base64")
        digest = hashlib.sha256(content).hexdigest()
        with self.connect() as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                parent = self._evidence(conn, evidence_id)
                parent_ce = self._resolve_case_evidence(conn, evidence_id, user_id, {"analyst"}, case_id)
                if parent_ce["status"] != "opened":
                    raise BusinessError("原始证据必须先开箱才能分析", 409, "evidence_not_opened")
                cur = conn.execute(
                    """INSERT INTO evidence(filename,sha256,size,content,current_custodian,created_by,created_at)
                       VALUES(?,?,?,?,?,?,?)""",
                    (filename.strip(), digest, len(content), content, user_id, user_id, now()),
                )
                child_id = cur.lastrowid
                conn.execute(
                    """INSERT INTO case_evidence(case_id,evidence_id,label,status,legal_hold,retention_until,created_by,created_at)
                       VALUES(?,?,?, 'derivative',0,?,?,?)""",
                    (parent_ce["case_id"], child_id, label.strip(), parent_ce["retention_until"], user_id, now()),
                )
                conn.execute(
                    "INSERT INTO derivatives(parent_evidence_id,child_evidence_id,method,actor_id,created_at) VALUES(?,?,?,?,?)",
                    (evidence_id, child_id, method.strip(), user_id, now()),
                )
                self._append_event(conn, evidence_id, "ANALYZE", user_id, from_person=parent["current_custodian"], note=f"生成衍生证据 #{child_id}: {method.strip()}")
                self._append_event(conn, child_id, "INGEST", user_id, from_person=parent["current_custodian"], to_person=user_id, note=f"由证据 #{evidence_id} 派生，SHA-256 {digest}")
                self._audit(conn, parent_ce["case_id"], user_id, "evidence.derive", {"parent_id": evidence_id, "child_id": child_id, "method": method.strip(), "sha256": digest})
                return {"id": child_id, "parent_id": evidence_id, "label": label.strip(), "sha256": digest, "status": "derivative"}
            except sqlite3.IntegrityError:
                conn.rollback()
                raise BusinessError("衍生证据标签已存在", 409, "label_exists")
            except Exception:
                conn.rollback()
                raise

    def set_hold(self, user_id, evidence_id, hold, reason, case_id=None):
        if len(reason.strip()) < 5:
            raise BusinessError("法律保留原因至少 5 字", 422, "reason_required")
        with self.connect() as conn:
            row = self._evidence(conn, evidence_id)
            ce = self._resolve_case_evidence(conn, evidence_id, user_id, case_id=case_id)
            case = self._case(conn, ce["case_id"])
            if user_id != case["created_by"]:
                self._member(conn, ce["case_id"], user_id, {"auditor"})
            conn.execute("UPDATE case_evidence SET legal_hold=? WHERE id=?", (int(bool(hold)), ce["id"]))
            event = "HOLD_SET" if hold else "HOLD_CLEARED"
            self._append_event(conn, evidence_id, event, user_id, note=reason.strip())
            self._audit(conn, ce["case_id"], user_id, "evidence.hold", {"evidence_id": evidence_id, "hold": bool(hold), "reason": reason.strip()})
            return {"id": evidence_id, "legal_hold": bool(hold)}

    def release(self, user_id, evidence_id, recipient, note="", case_id=None):
        if not recipient.strip():
            raise BusinessError("接收方不能为空", 422, "recipient_required")
        with self.connect() as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                row = self._evidence(conn, evidence_id)
                ce = self._resolve_case_evidence(conn, evidence_id, user_id, {"custodian"}, case_id)
                if ce["legal_hold"]:
                    raise BusinessError("存在法律保留，禁止释放证据", 409, "legal_hold_active")
                if ce["status"] == "released":
                    raise BusinessError("证据已经释放", 409, "already_released")
                self._append_event(conn, evidence_id, "RELEASE", user_id, from_person=row["current_custodian"], to_person=recipient.strip(), note=note.strip())
                conn.execute("UPDATE case_evidence SET status='released' WHERE id=?", (ce["id"],))
                self._audit(conn, ce["case_id"], user_id, "evidence.release", {"evidence_id": evidence_id, "recipient": recipient.strip()})
                return {"id": evidence_id, "status": "released", "recipient": recipient.strip()}
            except Exception:
                conn.rollback()
                raise

    def report(self, user_id, case_id):
        with self.connect() as conn:
            self._member(conn, case_id, user_id)
            case = self._case(conn, case_id)
            items, all_valid = [], True
            for ce in conn.execute(
                """SELECT ce.*, e.filename, e.sha256, e.size, e.content, e.current_custodian
                   FROM case_evidence ce JOIN evidence e ON e.id=ce.evidence_id
                   WHERE ce.case_id=? ORDER BY ce.id""",
                (case_id,),
            ).fetchall():
                hash_valid = hashlib.sha256(ce["content"]).hexdigest() == ce["sha256"]
                events = conn.execute("SELECT * FROM custody_events WHERE evidence_id=? ORDER BY sequence", (ce["evidence_id"],)).fetchall()
                expected_prev, chain_valid = "GENESIS", True
                for e in events:
                    payload = {
                        "evidence_id": e["evidence_id"], "sequence": e["sequence"], "event_type": e["event_type"],
                        "actor_id": e["actor_id"], "from_person": e["from_person"], "to_person": e["to_person"],
                        "location": e["location"], "note": e["note"], "previous_hash": e["previous_hash"], "created_at": e["created_at"],
                    }
                    if e["previous_hash"] != expected_prev or self._event_hash(payload) != e["event_hash"]:
                        chain_valid = False
                    expected_prev = e["event_hash"]
                all_valid = all_valid and hash_valid and chain_valid
                items.append({
                    "id": ce["evidence_id"], "case_evidence_id": ce["id"], "label": ce["label"],
                    "filename": ce["filename"], "sha256": ce["sha256"], "size": ce["size"],
                    "status": ce["status"], "current_custodian": ce["current_custodian"],
                    "legal_hold": bool(ce["legal_hold"]), "retention_until": ce["retention_until"],
                    "hash_valid": hash_valid, "chain_valid": chain_valid,
                    "events": [dict(e) for e in events],
                    "derivatives": [dict(x) for x in conn.execute(
                        "SELECT * FROM derivatives WHERE parent_evidence_id=? ORDER BY id", (ce["evidence_id"],)
                    ).fetchall()],
                })
            audit = conn.execute("SELECT * FROM audit_log WHERE case_id=? ORDER BY id", (case_id,)).fetchall()
            return {
                "case": dict(case), "generated_at": now(), "overall_integrity_valid": all_valid,
                "evidence_count": len(items), "evidence": items,
                "archive": self._archive_summary(conn, case_id),
                "audit": [dict(a) | {"detail": json.loads(a["detail"])} for a in audit],
            }

    # ------------------------------------------------------------------
    # 归档封存清单核验
    # ------------------------------------------------------------------
    @staticmethod
    def _state_hash(case_rows, item_rows):
        """汇总案件权威状态与清单权威状态，用于判断是否需要作废重算。"""
        h = hashlib.sha256()
        for r in case_rows:
            h.update(str(r["evidence_id"]).encode())
            h.update(str(r["sha256"]).encode())
            h.update(str(r["status"]).encode())
            h.update(str(r["legal_hold"]).encode())
            h.update(str(r["current_custodian"]).encode())
        for r in item_rows:
            h.update(str(r["evidence_id"] or "").encode())
            h.update(str(r["sha256"]).encode())
        return h.hexdigest()

    def _compute_state_hash(self, conn, case_id, manifest_id):
        case_rows = conn.execute(
            """SELECT ce.evidence_id, e.sha256, ce.status, ce.legal_hold, e.current_custodian
               FROM case_evidence ce JOIN evidence e ON e.id=ce.evidence_id
               WHERE ce.case_id=? ORDER BY ce.id""",
            (case_id,),
        ).fetchall()
        item_rows = conn.execute(
            "SELECT evidence_id, sha256 FROM archive_item WHERE manifest_id=? ORDER BY id", (manifest_id,)
        ).fetchall()
        return self._state_hash(case_rows, item_rows)

    def _verify_item(self, conn, item, case_id):
        """核验单条清单项：缺件 / 损坏件 / 换出 / 核验通过。原保管记录只读不动。"""
        evidence = None
        if item["evidence_id"]:
            evidence = conn.execute("SELECT * FROM evidence WHERE id=?", (item["evidence_id"],)).fetchone()
        if evidence is None and item["sha256"]:
            evidence = conn.execute("SELECT * FROM evidence WHERE sha256=?", (item["sha256"],)).fetchone()
        ce = None
        if evidence is not None:
            ce = conn.execute(
                "SELECT * FROM case_evidence WHERE case_id=? AND evidence_id=?", (case_id, evidence["id"])
            ).fetchone()
        if evidence is None or ce is None:
            result, reason = "missing", "清单中的证据在案件保管记录中不存在（缺件）"
        else:
            content_ok = hashlib.sha256(evidence["content"]).hexdigest() == evidence["sha256"]
            manifest_sha_ok = (not item["sha256"]) or (item["sha256"] == evidence["sha256"])
            if not content_ok:
                result, reason = "damaged", "证据内容哈希校验不通过，疑似损坏或被篡改（损坏件）"
            elif not manifest_sha_ok:
                result, reason = "damaged", "清单登记哈希与证据实际哈希不一致（损坏件）"
            elif ce["status"] == "released":
                result, reason = "swapped_out", "证据已被释放出归档封存（换出记录）"
            else:
                result, reason = "verified", "封存清单与保管记录一致"
        conn.execute(
            "UPDATE archive_item SET result=?, reason=?, processed_at=? WHERE id=?",
            (result, reason, now(), item["id"]),
        )
        return result, reason

    def _recompute_manifest(self, conn, manifest, case_id):
        """作废旧结果并重算：先全部置为 pending，再逐条核验。"""
        conn.execute("UPDATE archive_item SET result='pending', reason='', processed_at=NULL WHERE manifest_id=?", (manifest["id"],))
        items = conn.execute("SELECT * FROM archive_item WHERE manifest_id=? ORDER BY id", (manifest["id"],)).fetchall()
        summary = {"verified": 0, "missing": 0, "damaged": 0, "swapped_out": 0, "pending": 0}
        for it in items:
            result, _ = self._verify_item(conn, it, case_id)
            summary[result] += 1
        # 同步批次状态：仍有未处理条目的批次标记为 failed
        for b in conn.execute("SELECT id FROM archive_batch WHERE manifest_id=?", (manifest["id"],)).fetchall():
            left = conn.execute(
                "SELECT COUNT(*) AS c FROM archive_item WHERE batch_id=? AND result='pending'", (b["id"],)
            ).fetchone()["c"]
            conn.execute(
                "UPDATE archive_batch SET status=?, processed_at=? WHERE id=?",
                ("completed" if left == 0 else "failed", now(), b["id"]),
            )
        state_hash = self._compute_state_hash(conn, case_id, manifest["id"])
        conn.execute("UPDATE archive_manifest SET state_hash=? WHERE id=?", (state_hash, manifest["id"]))
        return summary

    def _recompute_if_stale(self, conn, manifest):
        """清单或案件权威状态一变就作废重算。"""
        current = self._compute_state_hash(conn, manifest["case_id"], manifest["id"])
        if current != manifest["state_hash"]:
            return self._recompute_manifest(conn, manifest, manifest["case_id"])
        items = conn.execute("SELECT result FROM archive_item WHERE manifest_id=?", (manifest["id"],)).fetchall()
        summary = {"verified": 0, "missing": 0, "damaged": 0, "swapped_out": 0, "pending": 0}
        for it in items:
            summary[it["result"]] += 1
        return summary

    def _archive_summary(self, conn, case_id):
        manifests = conn.execute(
            "SELECT * FROM archive_manifest WHERE case_id=? ORDER BY id", (case_id,)
        ).fetchall()
        out = []
        for m in manifests:
            summary = self._recompute_if_stale(conn, m)
            batches = conn.execute(
                "SELECT * FROM archive_batch WHERE manifest_id=? ORDER BY batch_number", (m["id"],)
            ).fetchall()
            out.append({
                "manifest_id": m["id"], "manifest_number": m["manifest_number"], "status": m["status"],
                "batch_count": len(batches), "batches": [
                    {"id": b["id"], "batch_number": b["batch_number"], "status": b["status"], "processed_at": b["processed_at"]}
                    for b in batches
                ],
                "summary": summary,
            })
        return out

    def submit_manifest(self, user_id, case_id, manifest_number, items):
        manifest_number = manifest_number.strip()
        if not manifest_number:
            raise BusinessError("封存清单编号不能为空", 422, "invalid_manifest")
        if not isinstance(items, list) or not items:
            raise BusinessError("封存清单条目不能为空", 422, "invalid_manifest")
        cleaned = []
        for it in items:
            if not isinstance(it, dict):
                raise BusinessError("清单条目必须是对象", 422, "invalid_manifest")
            sha = str(it.get("sha256", "")).strip()
            eid = it.get("evidence_id")
            if eid is not None:
                try:
                    eid = int(eid)
                except (TypeError, ValueError):
                    raise BusinessError("evidence_id 必须是整数", 422, "invalid_manifest")
            if not sha and eid is None:
                raise BusinessError("清单条目必须提供 sha256 或 evidence_id", 422, "invalid_manifest")
            cleaned.append({"evidence_id": eid, "sha256": sha, "label": str(it.get("label", "")).strip()})
        with self.connect() as conn:
            self._member(conn, case_id, user_id)
            try:
                conn.execute("BEGIN IMMEDIATE")
                # 清单头幂等：同一封存清单并发提交只保存第一条
                conn.execute(
                    "INSERT OR IGNORE INTO archive_manifest(manifest_number,case_id,status,state_hash,created_by,created_at) VALUES(?,?, 'active','',?,?)",
                    (manifest_number, case_id, user_id, now()),
                )
                manifest = conn.execute("SELECT * FROM archive_manifest WHERE manifest_number=?", (manifest_number,)).fetchone()
                if manifest["case_id"] != case_id:
                    raise BusinessError("封存清单编号已被其他案件占用", 409, "manifest_exists")
                next_batch = conn.execute(
                    "SELECT COALESCE(MAX(batch_number),0)+1 AS n FROM archive_batch WHERE manifest_id=?", (manifest["id"],)
                ).fetchone()["n"]
                cur = conn.execute(
                    "INSERT INTO archive_batch(manifest_id,batch_number,status,created_at) VALUES(?,?, 'pending',?)",
                    (manifest["id"], next_batch, now()),
                )
                batch_id = cur.lastrowid
                for it in cleaned:
                    conn.execute(
                        """INSERT OR IGNORE INTO archive_item(batch_id,manifest_id,evidence_id,sha256,label,result,reason)
                           VALUES(?,?,?,?,?, 'pending','')""",
                        (batch_id, manifest["id"], it["evidence_id"], it["sha256"], it["label"]),
                    )
                conn.execute("UPDATE archive_batch SET status='processing' WHERE id=?", (batch_id,))
                # 按阶段核验本批次条目
                batch_items = conn.execute(
                    "SELECT * FROM archive_item WHERE batch_id=? ORDER BY id", (batch_id,)
                ).fetchall()
                results = []
                for it in batch_items:
                    result, reason = self._verify_item(conn, it, case_id)
                    results.append({"sha256": it["sha256"], "evidence_id": it["evidence_id"], "result": result, "reason": reason})
                conn.execute("UPDATE archive_batch SET status='completed', processed_at=? WHERE id=?", (now(), batch_id))
                # 重算整单状态哈希
                state_hash = self._compute_state_hash(conn, case_id, manifest["id"])
                conn.execute("UPDATE archive_manifest SET state_hash=? WHERE id=?", (state_hash, manifest["id"]))
                self._audit(conn, case_id, user_id, "archive.submit", {"manifest_number": manifest_number, "batch_number": next_batch, "count": len(results)})
                return {
                    "manifest_id": manifest["id"], "manifest_number": manifest_number,
                    "batch_id": batch_id, "batch_number": next_batch, "status": "completed",
                    "results": results,
                }
            except sqlite3.IntegrityError:
                conn.rollback()
                raise BusinessError("封存清单编号已存在", 409, "manifest_exists")
            except Exception:
                conn.rollback()
                raise

    def replay_manifest(self, user_id, manifest_id):
        """中断失败后重放：补全还没处理的记录（pending 条目）。"""
        with self.connect() as conn:
            manifest = conn.execute("SELECT * FROM archive_manifest WHERE id=?", (manifest_id,)).fetchone()
            if not manifest:
                raise BusinessError("封存清单不存在", 404, "not_found")
            self._member(conn, manifest["case_id"], user_id)
            try:
                conn.execute("BEGIN IMMEDIATE")
                # 重放前先按权威状态作废重算，再补全 pending 条目
                self._recompute_if_stale(conn, manifest)
                pending = conn.execute(
                    "SELECT * FROM archive_item WHERE manifest_id=? AND result='pending' ORDER BY id", (manifest_id,)
                ).fetchall()
                processed = []
                for it in pending:
                    result, reason = self._verify_item(conn, it, manifest["case_id"])
                    processed.append({"sha256": it["sha256"], "result": result, "reason": reason})
                state_hash = self._compute_state_hash(conn, manifest["case_id"], manifest_id)
                conn.execute("UPDATE archive_manifest SET state_hash=? WHERE id=?", (state_hash, manifest_id))
                # 标记仍有未处理条目的批次为 failed，已处理完的为 completed
                batches = conn.execute("SELECT * FROM archive_batch WHERE manifest_id=?", (manifest_id,)).fetchall()
                for b in batches:
                    left = conn.execute(
                        "SELECT COUNT(*) AS c FROM archive_item WHERE batch_id=? AND result='pending'", (b["id"],)
                    ).fetchone()["c"]
                    conn.execute(
                        "UPDATE archive_batch SET status=?, processed_at=? WHERE id=?",
                        ("completed" if left == 0 else "failed", now(), b["id"]),
                    )
                self._audit(conn, manifest["case_id"], user_id, "archive.replay", {"manifest_id": manifest_id, "processed": len(processed)})
                return {"manifest_id": manifest_id, "processed_count": len(processed), "processed": processed}
            except Exception:
                conn.rollback()
                raise

    def get_manifest(self, user_id, manifest_id):
        with self.connect() as conn:
            manifest = conn.execute("SELECT * FROM archive_manifest WHERE id=?", (manifest_id,)).fetchone()
            if not manifest:
                raise BusinessError("封存清单不存在", 404, "not_found")
            self._member(conn, manifest["case_id"], user_id)
            summary = self._recompute_if_stale(conn, manifest)
            batches = conn.execute(
                "SELECT * FROM archive_batch WHERE manifest_id=? ORDER BY batch_number", (manifest_id,)
            ).fetchall()
            items = conn.execute(
                "SELECT * FROM archive_item WHERE manifest_id=? ORDER BY id", (manifest_id,)
            ).fetchall()
            return {
                "manifest_id": manifest["id"], "manifest_number": manifest["manifest_number"],
                "case_id": manifest["case_id"], "status": manifest["status"],
                "state_hash": manifest["state_hash"], "summary": summary,
                "batches": [
                    {"id": b["id"], "batch_number": b["batch_number"], "status": b["status"], "created_at": b["created_at"], "processed_at": b["processed_at"]}
                    for b in batches
                ],
                "items": [
                    {"id": it["id"], "batch_id": it["batch_id"], "evidence_id": it["evidence_id"],
                     "sha256": it["sha256"], "label": it["label"], "result": it["result"],
                     "reason": it["reason"], "processed_at": it["processed_at"]}
                    for it in items
                ],
            }

    def list_manifests(self, user_id, case_id):
        with self.connect() as conn:
            self._member(conn, case_id, user_id)
            manifests = conn.execute(
                "SELECT * FROM archive_manifest WHERE case_id=? ORDER BY id", (case_id,)
            ).fetchall()
            out = []
            for m in manifests:
                summary = self._recompute_if_stale(conn, m)
                batch_count = conn.execute(
                    "SELECT COUNT(*) AS c FROM archive_batch WHERE manifest_id=?", (m["id"],)
                ).fetchone()["c"]
                out.append({
                    "manifest_id": m["id"], "manifest_number": m["manifest_number"], "status": m["status"],
                    "batch_count": batch_count, "summary": summary,
                })
            return out


class Handler(BaseHTTPRequestHandler):
    server_version = "EvidenceCustody/1.0"
    def _store(self): return self.server.store  # type: ignore[attr-defined]
    def _body(self):
        length = int(self.headers.get("Content-Length", "0"))
        try: data = json.loads(self.rfile.read(length) or b"{}")
        except (json.JSONDecodeError, UnicodeDecodeError): raise BusinessError("请求体必须是合法 JSON", 400, "invalid_json")
        if not isinstance(data, dict): raise BusinessError("JSON 顶层必须是对象", 422, "invalid_json")
        return data
    def _send(self, status, payload):
        body=json.dumps(payload,ensure_ascii=False).encode(); self.send_response(status)
        self.send_header("Content-Type","application/json; charset=utf-8"); self.send_header("Content-Length",str(len(body)))
        self.end_headers(); self.wfile.write(body)
    def _dispatch(self, method):
        path=urlparse(self.path).path.rstrip("/") or "/"; parts=[p for p in path.split("/") if p]
        user=self.headers.get("X-User-Id",""); store=self._store()
        if method=="GET" and path=="/":
            body=(BASE_DIR/"web"/"index.html").read_bytes(); self.send_response(200)
            self.send_header("Content-Type","text/html; charset=utf-8"); self.send_header("Content-Length",str(len(body)))
            self.end_headers(); self.wfile.write(body); return
        if method=="GET" and path=="/health": return self._send(200,{"ok":True})
        if parts==["api","cases"] and method=="POST":
            d=self._body(); return self._send(201,store.create_case(user,d.get("case_number",""),d.get("title","")))
        if len(parts)==4 and parts[:2]==["api","cases"] and parts[3]=="members" and method=="POST":
            d=self._body(); return self._send(201,store.add_member(user,int(parts[2]),d.get("user_id",""),d.get("role","")))
        if len(parts)==4 and parts[:2]==["api","cases"] and parts[3]=="evidence" and method=="POST":
            d=self._body(); return self._send(201,store.ingest_evidence(user,int(parts[2]),d.get("label",""),d.get("filename",""),d.get("content_b64",""),d.get("retention_until",""),d.get("custodian")))
        if len(parts)==4 and parts[:2]==["api","cases"] and parts[3]=="report" and method=="GET":
            return self._send(200,store.report(user,int(parts[2])))
        if len(parts)==4 and parts[:2]==["api","cases"] and parts[3]=="archive" and method=="GET":
            return self._send(200,store.list_manifests(user,int(parts[2])))
        if len(parts)==4 and parts[:2]==["api","cases"] and parts[3]=="archive" and method=="POST":
            d=self._body(); return self._send(201,store.submit_manifest(user,int(parts[2]),d.get("manifest_number",""),d.get("items",[])))
        if len(parts)==3 and parts[:2]==["api","archive"] and method=="GET":
            return self._send(200,store.get_manifest(user,int(parts[2])))
        if len(parts)==4 and parts[:2]==["api","archive"] and parts[3]=="replay" and method=="POST":
            return self._send(200,store.replay_manifest(user,int(parts[2])))
        if len(parts)>=3 and parts[:2]==["api","evidence"]:
            evidence_id=int(parts[2])
            if len(parts)==3 and method=="GET":
                qs=urlparse(self.path).query
                params=dict(p.split("=",1) for p in qs.split("&") if "=" in p) if qs else {}
                cid=int(params["case_id"]) if params.get("case_id") else None
                include_content=("content" in params) or bool(qs)
                return self._send(200,store.get_evidence(user,evidence_id,include_content,cid))
            if len(parts)==4 and method=="POST":
                d=self._body()
                cid=d.get("case_id")
                if parts[3]=="transfer": return self._send(200,store.transfer(user,evidence_id,d.get("to_person",""),d.get("location",""),d.get("note",""),cid))
                if parts[3]=="open": return self._send(200,store.open_evidence(user,evidence_id,d.get("location",""),d.get("note",""),cid))
                if parts[3]=="derive": return self._send(201,store.derive(user,evidence_id,d.get("method",""),d.get("label",""),d.get("filename",""),d.get("content_b64",""),cid))
                if parts[3]=="release": return self._send(200,store.release(user,evidence_id,d.get("recipient",""),d.get("note",""),cid))
                if parts[3]=="hold": return self._send(200,store.set_hold(user,evidence_id,bool(d.get("hold")),d.get("reason",""),cid))
        raise BusinessError("接口不存在",404,"not_found")
    def _handle(self, method):
        try: self._dispatch(method)
        except BusinessError as exc: self._send(exc.status,{"error":{"code":exc.code,"message":exc.message}})
        except (ValueError,TypeError): self._send(400,{"error":{"code":"invalid_path","message":"路径参数格式错误"}})
        except Exception as exc: self._send(500,{"error":{"code":"internal_error","message":str(exc)}})
    def do_GET(self): self._handle("GET")
    def do_POST(self): self._handle("POST")
    def do_DELETE(self): self._send(405,{"error":{"code":"immutable_audit","message":"证据和保管记录不提供删除接口"}})
    def log_message(self, fmt, *args): print(f"{self.address_string()} - {fmt % args}")


class CustodyServer(ThreadingHTTPServer):
    daemon_threads=True
    def __init__(self,address,store): self.store=store; super().__init__(address,Handler)


def main():
    parser=argparse.ArgumentParser(description="法律证据保管与流转后台")
    parser.add_argument("--db",default=str(DEFAULT_DB)); parser.add_argument("--port",type=int,default=8105)
    parser.add_argument("--init",action="store_true"); parser.add_argument("--seed",action="store_true")
    args=parser.parse_args(); store=CustodyStore(args.db); store.init_schema()
    if args.seed: store.seed()
    if args.init or args.seed: print(f"数据库已初始化: {args.db}"); return
    server=CustodyServer(("127.0.0.1",args.port),store); print(f"证据保管系统运行于 http://127.0.0.1:{args.port}")
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally: server.server_close()

if __name__=="__main__": main()
