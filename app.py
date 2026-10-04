"""法律证据保管与流转后台。

在基础入册/开箱/移交/衍生/释放能力之上提供：

* 跨案件复用：同一份内容（SHA-256 相同）再次入册时复用原保管号、保管位置和
  共享保管事件链；每个案件持有独立的入册记录，自行管理释放权限与法律保留。
* 归档核验：归档中间件分阶段提交封存清单，同一清单并发提交只保留第一条；
  处理进度逐条落库，中断后重放补全；清单或案件权威状态变化时旧结果作废重算，
  标出缺件、损坏件和换出记录，物证原始保管记录始终不被修改。
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import sqlite3
import threading
from collections import Counter
from datetime import date, datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB = BASE_DIR / "custody.db"
MEMBER_ROLES = {"custodian", "analyst", "auditor"}
ENTRY_FINAL_STATUSES = {"verified", "missing", "damaged", "swapped_out"}


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
                -- 物证本体：跨案件共享，保管号、内容、当前位置和事件链都挂在这里
                CREATE TABLE IF NOT EXISTS custody_items(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    custody_number TEXT NOT NULL UNIQUE,
                    sha256 TEXT NOT NULL UNIQUE,
                    filename TEXT NOT NULL, size INTEGER NOT NULL, content BLOB NOT NULL,
                    physical_status TEXT NOT NULL DEFAULT 'sealed'
                        CHECK(physical_status IN ('sealed','opened','released')),
                    current_custodian TEXT NOT NULL, current_location TEXT NOT NULL DEFAULT '',
                    first_case_id INTEGER NOT NULL REFERENCES cases(id),
                    first_evidence_id INTEGER,
                    created_by TEXT NOT NULL REFERENCES users(id), created_at TEXT NOT NULL
                );
                -- 案件入册记录：同一物证可在多个案件各有一条，状态/法律保留/释放相互独立
                CREATE TABLE IF NOT EXISTS evidence(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES custody_items(id),
                    case_id INTEGER NOT NULL REFERENCES cases(id), label TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'custody'
                        CHECK(status IN ('custody','opened','released','derivative')),
                    legal_hold INTEGER NOT NULL DEFAULT 0 CHECK(legal_hold IN (0,1)),
                    retention_until TEXT NOT NULL,
                    release_recipient TEXT, released_at TEXT,
                    created_by TEXT NOT NULL REFERENCES users(id),
                    created_at TEXT NOT NULL, UNIQUE(case_id,label)
                );
                -- 共享保管事件链：按物证本体串联，case_id 标记动作归属案件
                CREATE TABLE IF NOT EXISTS custody_events(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES custody_items(id),
                    case_id INTEGER REFERENCES cases(id), evidence_id INTEGER REFERENCES evidence(id),
                    sequence INTEGER NOT NULL,
                    event_type TEXT NOT NULL CHECK(event_type IN
                        ('INGEST','CROSS_REUSE','TRANSFER','OPEN','ANALYZE','RELEASE','HOLD_SET','HOLD_CLEARED')),
                    actor_id TEXT NOT NULL REFERENCES users(id), from_person TEXT,
                    to_person TEXT, location TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '',
                    previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL, UNIQUE(item_id,sequence)
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
                -- 归档封存清单（批次）
                CREATE TABLE IF NOT EXISTS archive_batches(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    batch_number TEXT NOT NULL UNIQUE,
                    case_id INTEGER NOT NULL REFERENCES cases(id),
                    stage TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'received'
                        CHECK(status IN ('received','processing','completed','failed')),
                    submitted_by TEXT NOT NULL REFERENCES users(id),
                    submitted_at TEXT NOT NULL,
                    recompute_count INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT NOT NULL DEFAULT ''
                );
                -- 清单条目及核验结果；state_fingerprint 是处理时的权威状态快照
                CREATE TABLE IF NOT EXISTS archive_entries(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    batch_id INTEGER NOT NULL REFERENCES archive_batches(id),
                    custody_number TEXT NOT NULL,
                    expected_sha256 TEXT NOT NULL DEFAULT '',
                    expected_location TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'pending'
                        CHECK(status IN ('pending','verified','missing','damaged','swapped_out')),
                    reason TEXT NOT NULL DEFAULT '',
                    evidence_id INTEGER,
                    state_fingerprint TEXT NOT NULL DEFAULT '',
                    previous_status TEXT NOT NULL DEFAULT '',
                    recompute_count INTEGER NOT NULL DEFAULT 0,
                    processed_at TEXT,
                    UNIQUE(batch_id,custody_number)
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
                    ("analyst1", "电子数据分析员"), ("auditor1", "案件审计员"),
                    ("archive_mw", "归档中间件服务账号"), ("outsider", "外部人员"),
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

    @staticmethod
    def _fingerprint(data):
        canonical = json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(canonical).hexdigest()

    def _append_event(self, conn, item_id, case_id, evidence_id, event_type, actor,
                      from_person="", to_person="", location="", note=""):
        previous = conn.execute(
            "SELECT event_hash,sequence FROM custody_events WHERE item_id=? ORDER BY sequence DESC LIMIT 1",
            (item_id,),
        ).fetchone()
        sequence = (previous["sequence"] + 1) if previous else 1
        previous_hash = previous["event_hash"] if previous else "GENESIS"
        payload = {
            "item_id": item_id, "case_id": case_id, "sequence": sequence, "event_type": event_type,
            "actor_id": actor, "from_person": from_person or None, "to_person": to_person or None,
            "location": location, "note": note, "previous_hash": previous_hash, "created_at": now(),
        }
        digest = self._event_hash(payload)
        cur = conn.execute(
            """INSERT INTO custody_events(item_id,case_id,evidence_id,sequence,event_type,
                   actor_id,from_person,to_person,location,note,previous_hash,event_hash,created_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (item_id, case_id, evidence_id, sequence, event_type, actor,
             from_person or None, to_person or None, location, note, previous_hash, digest, payload["created_at"]),
        )
        return cur.lastrowid, digest

    def _chain_tip(self, conn, item_id):
        tip = conn.execute(
            "SELECT sequence,event_hash FROM custody_events WHERE item_id=? ORDER BY sequence DESC LIMIT 1",
            (item_id,),
        ).fetchone()
        return None if tip is None else f"{tip['sequence']}:{tip['event_hash']}"

    def _verify_chain(self, conn, item_id):
        events = conn.execute(
            "SELECT * FROM custody_events WHERE item_id=? ORDER BY sequence", (item_id,)
        ).fetchall()
        expected_prev, valid = "GENESIS", True
        for e in events:
            payload = {
                "item_id": e["item_id"], "case_id": e["case_id"], "sequence": e["sequence"],
                "event_type": e["event_type"], "actor_id": e["actor_id"],
                "from_person": e["from_person"], "to_person": e["to_person"],
                "location": e["location"], "note": e["note"],
                "previous_hash": e["previous_hash"], "created_at": e["created_at"],
            }
            if e["previous_hash"] != expected_prev or self._event_hash(payload) != e["event_hash"]:
                valid = False
            expected_prev = e["event_hash"]
        return valid, [dict(e) for e in events]

    def _custody_number(self, conn):
        next_id = conn.execute("SELECT COALESCE(MAX(id),0)+1 FROM custody_items").fetchone()[0]
        return next_id, f"EV-{next_id:06d}"

    def _create_item(self, conn, case_id, filename, content, digest, custodian, created_by):
        item_id, number = self._custody_number(conn)
        conn.execute(
            """INSERT INTO custody_items(id,custody_number,sha256,filename,size,content,
                   current_custodian,first_case_id,created_by,created_at)
               VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (item_id, number, digest, filename, len(content), content,
             custodian, case_id, created_by, now()),
        )
        return item_id, number

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
            try:
                conn.execute("BEGIN IMMEDIATE")
                self._member(conn, case_id, user_id, {"custodian"})
                if not custodian:
                    raise BusinessError("保管人不能为空", 422, "invalid_custodian")
                item = conn.execute(
                    "SELECT * FROM custody_items WHERE sha256=?", (digest,)
                ).fetchone()
                reused = item is not None
                if item is None:
                    item_id, number = self._create_item(conn, case_id, filename, content, digest, custodian, user_id)
                else:
                    item_id, number = item["id"], item["custody_number"]
                try:
                    cur = conn.execute(
                        """INSERT INTO evidence(item_id,case_id,label,status,retention_until,created_by,created_at)
                           VALUES(?,?,?,'custody',?,?,?)""",
                        (item_id, case_id, label, retention_until, user_id, now()),
                    )
                except sqlite3.IntegrityError:
                    raise BusinessError("该案件中的证据标签已存在", 409, "label_exists")
                evidence_id = cur.lastrowid
                if reused:
                    origin_case = conn.execute(
                        "SELECT case_number FROM cases WHERE id=?", (item["first_case_id"],)
                    ).fetchone()
                    self._append_event(
                        conn, item_id, case_id, evidence_id, "CROSS_REUSE", user_id,
                        from_person=item["current_custodian"], location=item["current_location"],
                        note=(f"案件再次入册复用原保管号 {number}（首次入册案件 "
                              f"{origin_case['case_number'] if origin_case else item['first_case_id']}，"
                              f"当前位置 {item['current_location'] or '未记录'}）"),
                    )
                    self._audit(conn, case_id, user_id, "evidence.reuse", {
                        "evidence_id": evidence_id, "item_id": item_id, "custody_number": number,
                        "sha256": digest, "label": label, "origin_case_id": item["first_case_id"],
                    })
                else:
                    conn.execute(
                        "UPDATE custody_items SET first_evidence_id=? WHERE id=?", (evidence_id, item_id)
                    )
                    self._append_event(
                        conn, item_id, case_id, evidence_id, "INGEST", user_id,
                        to_person=custodian, note=f"入册 SHA-256 {digest}",
                    )
                    self._audit(conn, case_id, user_id, "evidence.ingest", {
                        "evidence_id": evidence_id, "item_id": item_id, "custody_number": number,
                        "sha256": digest, "label": label,
                    })
                return {
                    "id": evidence_id, "item_id": item_id, "custody_number": number,
                    "label": label, "sha256": digest, "size": len(content),
                    "status": "custody", "current_custodian": custodian, "reused": reused,
                }
            except BusinessError:
                conn.rollback()
                raise
            except Exception:
                conn.rollback()
                raise

    def _evidence(self, conn, evidence_id):
        row = conn.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()
        if not row:
            raise BusinessError("证据不存在", 404, "not_found")
        return row

    def _shared_view(self, conn, item):
        registrations = conn.execute(
            """SELECT e.id AS evidence_id,e.case_id,c.case_number,e.label,e.status,e.legal_hold,
                      e.release_recipient,e.released_at
               FROM evidence e JOIN cases c ON c.id=e.case_id
               WHERE e.item_id=? ORDER BY e.id""",
            (item["id"],),
        ).fetchall()
        return {
            "item_id": item["id"], "custody_number": item["custody_number"],
            "physical_status": item["physical_status"],
            "current_custodian": item["current_custodian"],
            "current_location": item["current_location"],
            "first_case_id": item["first_case_id"], "first_evidence_id": item["first_evidence_id"],
            "registrations": [dict(r) | {"legal_hold": bool(r["legal_hold"])} for r in registrations],
        }

    def get_evidence(self, user_id, evidence_id, include_content=False):
        with self.connect() as conn:
            row = self._evidence(conn, evidence_id)
            self._member(conn, row["case_id"], user_id)
            item = conn.execute("SELECT * FROM custody_items WHERE id=?", (row["item_id"],)).fetchone()
            chain_valid, events = self._verify_chain(conn, item["id"])
            result = {
                "id": row["id"], "case_id": row["case_id"], "label": row["label"],
                "status": row["status"], "legal_hold": bool(row["legal_hold"]),
                "retention_until": row["retention_until"],
                "release_recipient": row["release_recipient"], "released_at": row["released_at"],
                "filename": item["filename"], "sha256": item["sha256"], "size": item["size"],
                "integrity_valid": hashlib.sha256(item["content"]).hexdigest() == item["sha256"],
                "chain_valid": chain_valid,
                "shared_item": self._shared_view(conn, item),
                "events": events,
                "parent_evidence_id": conn.execute(
                    "SELECT parent_evidence_id FROM derivatives WHERE child_evidence_id=?", (evidence_id,)
                ).fetchone(),
                "derived_children": [dict(x) for x in conn.execute(
                    "SELECT * FROM derivatives WHERE parent_evidence_id=? ORDER BY id", (evidence_id,)
                ).fetchall()],
            }
            parent = result["parent_evidence_id"]
            result["parent_evidence_id"] = None if parent is None else parent["parent_evidence_id"]
            if include_content:
                result["content_b64"] = base64.b64encode(item["content"]).decode()
            return result

    def transfer(self, user_id, evidence_id, to_person, location, note=""):
        if not to_person.strip() or not location.strip():
            raise BusinessError("接收人和保管位置不能为空", 422, "invalid_transfer")
        with self.connect() as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                row = self._evidence(conn, evidence_id)
                self._member(conn, row["case_id"], user_id, {"custodian"})
                if row["status"] == "released":
                    raise BusinessError("本案件已放行该证据，不能再移交", 409, "evidence_released")
                item = conn.execute("SELECT * FROM custody_items WHERE id=?", (row["item_id"],)).fetchone()
                self._append_event(
                    conn, item["id"], row["case_id"], evidence_id, "TRANSFER", user_id,
                    from_person=item["current_custodian"], to_person=to_person.strip(),
                    location=location.strip(), note=note.strip(),
                )
                conn.execute(
                    "UPDATE custody_items SET current_custodian=?,current_location=? WHERE id=?",
                    (to_person.strip(), location.strip(), item["id"]),
                )
                self._audit(conn, row["case_id"], user_id, "custody.transfer", {
                    "evidence_id": evidence_id, "custody_number": item["custody_number"],
                    "to": to_person.strip(), "location": location.strip(),
                })
                return {
                    "id": evidence_id, "custody_number": item["custody_number"],
                    "current_custodian": to_person.strip(), "location": location.strip(),
                }
            except BusinessError:
                conn.rollback()
                raise
            except Exception:
                conn.rollback()
                raise

    def open_evidence(self, user_id, evidence_id, location, note=""):
        if not location.strip():
            raise BusinessError("开箱地点不能为空", 422, "location_required")
        with self.connect() as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                row = self._evidence(conn, evidence_id)
                self._member(conn, row["case_id"], user_id, {"custodian"})
                if row["status"] != "custody":
                    raise BusinessError("本案件入册记录不在封存状态，不能开箱", 409, "invalid_status")
                item = conn.execute("SELECT * FROM custody_items WHERE id=?", (row["item_id"],)).fetchone()
                self._append_event(
                    conn, item["id"], row["case_id"], evidence_id, "OPEN", user_id,
                    from_person=item["current_custodian"], location=location.strip(), note=note.strip(),
                )
                conn.execute("UPDATE evidence SET status='opened' WHERE id=?", (evidence_id,))
                conn.execute(
                    "UPDATE custody_items SET physical_status='opened',current_location=? WHERE id=?",
                    (location.strip(), item["id"]),
                )
                self._audit(conn, row["case_id"], user_id, "evidence.open", {
                    "evidence_id": evidence_id, "location": location.strip(),
                })
                return {"id": evidence_id, "status": "opened", "location": location.strip()}
            except BusinessError:
                conn.rollback()
                raise
            except Exception:
                conn.rollback()
                raise

    def derive(self, user_id, evidence_id, method, label, filename, content_b64):
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
                self._member(conn, parent["case_id"], user_id, {"analyst"})
                if parent["status"] != "opened":
                    raise BusinessError("原始证据必须先开箱才能分析", 409, "evidence_not_opened")
                parent_item = conn.execute(
                    "SELECT * FROM custody_items WHERE id=?", (parent["item_id"],)
                ).fetchone()
                existing = conn.execute(
                    "SELECT id FROM custody_items WHERE sha256=?", (digest,)
                ).fetchone()
                if existing:
                    raise BusinessError("衍生内容与已有物证相同，应走跨案件复用而不是新建", 409, "content_exists")
                child_item_id, child_number = self._create_item(
                    conn, parent["case_id"], filename.strip(), content, digest, user_id, user_id
                )
                try:
                    cur = conn.execute(
                        """INSERT INTO evidence(item_id,case_id,label,status,retention_until,created_by,created_at)
                           VALUES(?,?,?,'derivative',?,?,?)""",
                        (child_item_id, parent["case_id"], label.strip(),
                         parent["retention_until"], user_id, now()),
                    )
                except sqlite3.IntegrityError:
                    raise BusinessError("衍生证据标签已存在", 409, "label_exists")
                child_id = cur.lastrowid
                conn.execute(
                    "UPDATE custody_items SET first_evidence_id=? WHERE id=?", (child_id, child_item_id)
                )
                conn.execute(
                    "INSERT INTO derivatives(parent_evidence_id,child_evidence_id,method,actor_id,created_at) VALUES(?,?,?,?,?)",
                    (evidence_id, child_id, method.strip(), user_id, now()),
                )
                self._append_event(
                    conn, parent_item["id"], parent["case_id"], evidence_id, "ANALYZE", user_id,
                    from_person=parent_item["current_custodian"],
                    note=f"生成衍生证据 #{child_id}（保管号 {child_number}）: {method.strip()}",
                )
                self._append_event(
                    conn, child_item_id, parent["case_id"], child_id, "INGEST", user_id,
                    from_person=parent_item["current_custodian"], to_person=user_id,
                    note=f"由证据 #{evidence_id} 派生，SHA-256 {digest}",
                )
                self._audit(conn, parent["case_id"], user_id, "evidence.derive", {
                    "parent_id": evidence_id, "child_id": child_id,
                    "custody_number": child_number, "method": method.strip(), "sha256": digest,
                })
                return {
                    "id": child_id, "item_id": child_item_id, "custody_number": child_number,
                    "parent_id": evidence_id, "label": label.strip(), "sha256": digest, "status": "derivative",
                }
            except BusinessError:
                conn.rollback()
                raise
            except Exception:
                conn.rollback()
                raise

    def set_hold(self, user_id, evidence_id, hold, reason):
        if len(reason.strip()) < 5:
            raise BusinessError("法律保留原因至少 5 字", 422, "reason_required")
        with self.connect() as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                row = self._evidence(conn, evidence_id)
                case = self._case(conn, row["case_id"])
                if user_id != case["created_by"]:
                    self._member(conn, row["case_id"], user_id, {"auditor"})
                conn.execute("UPDATE evidence SET legal_hold=? WHERE id=?", (int(bool(hold)), evidence_id))
                event = "HOLD_SET" if hold else "HOLD_CLEARED"
                self._append_event(
                    conn, row["item_id"], row["case_id"], evidence_id, event, user_id, note=reason.strip()
                )
                self._audit(conn, row["case_id"], user_id, "evidence.hold", {
                    "evidence_id": evidence_id, "hold": bool(hold), "reason": reason.strip(),
                })
                return {"id": evidence_id, "legal_hold": bool(hold)}
            except BusinessError:
                conn.rollback()
                raise
            except Exception:
                conn.rollback()
                raise

    def release(self, user_id, evidence_id, recipient, note=""):
        """释放只作用于调用者所在案件的入册记录；其他案件的记录和权限不受影响。"""
        if not recipient.strip():
            raise BusinessError("接收方不能为空", 422, "recipient_required")
        with self.connect() as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                row = self._evidence(conn, evidence_id)
                # 权限按本入册记录所属案件校验，他案成员越权释放直接拒绝
                self._member(conn, row["case_id"], user_id, {"custodian"})
                if row["legal_hold"]:
                    raise BusinessError("本案件存在法律保留，禁止释放证据", 409, "legal_hold_active")
                if row["status"] == "released":
                    raise BusinessError("证据在本案件已经释放", 409, "already_released")
                item = conn.execute("SELECT * FROM custody_items WHERE id=?", (row["item_id"],)).fetchone()
                self._append_event(
                    conn, item["id"], row["case_id"], evidence_id, "RELEASE", user_id,
                    from_person=item["current_custodian"], to_person=recipient.strip(), note=note.strip(),
                )
                conn.execute(
                    "UPDATE evidence SET status='released',release_recipient=?,released_at=? WHERE id=?",
                    (recipient.strip(), now(), evidence_id),
                )
                # 所有案件都放行后，物证本体才算物理出库；只要还有一个案件在封就保留原位
                active = conn.execute(
                    "SELECT COUNT(*) AS n FROM evidence WHERE item_id=? AND status!='released'",
                    (item["id"],),
                ).fetchone()["n"]
                if active == 0:
                    conn.execute(
                        "UPDATE custody_items SET physical_status='released',current_custodian=? WHERE id=?",
                        (recipient.strip(), item["id"]),
                    )
                self._audit(conn, row["case_id"], user_id, "evidence.release", {
                    "evidence_id": evidence_id, "custody_number": item["custody_number"],
                    "recipient": recipient.strip(), "other_active_registrations": active,
                })
                return {
                    "id": evidence_id, "status": "released",
                    "custody_number": item["custody_number"], "recipient": recipient.strip(),
                    "other_case_registrations_remain": bool(active),
                }
            except BusinessError:
                conn.rollback()
                raise
            except Exception:
                conn.rollback()
                raise

    # ------------------------------------------------------------------
    # 归档核验
    # ------------------------------------------------------------------

    def _entry_fingerprint(self, conn, case_id, entry):
        """权威状态指纹：清单声明 + 物证本体 + 本案件入册记录 + 链尖。"""
        item = conn.execute(
            "SELECT * FROM custody_items WHERE custody_number=?", (entry["custody_number"],)
        ).fetchone()
        base = {
            "custody_number": entry["custody_number"],
            "expected_sha256": entry["expected_sha256"] or None,
            "expected_location": entry["expected_location"] or None,
        }
        if item is None:
            return self._fingerprint(base | {"present": False})
        base |= {
            "present": True, "item_sha256": item["sha256"],
            "actual_sha256": hashlib.sha256(item["content"]).hexdigest(),
            "physical_status": item["physical_status"],
            "current_custodian": item["current_custodian"],
            "current_location": item["current_location"],
            "chain_tip": self._chain_tip(conn, item["id"]),
        }
        reg = conn.execute(
            "SELECT * FROM evidence WHERE case_id=? AND item_id=?", (case_id, item["id"])
        ).fetchone()
        if reg is None:
            return self._fingerprint(base | {"registered": False})
        return self._fingerprint(base | {
            "registered": True, "reg_status": reg["status"],
            "legal_hold": reg["legal_hold"], "release_recipient": reg["release_recipient"],
        })

    def _evaluate_entry(self, conn, case_id, entry):
        """按当前权威状态重算单条记录，返回 (状态, 原因, 入册记录id, 指纹)。"""
        number = entry["custody_number"]
        declared_sha = entry["expected_sha256"] or None
        declared_location = entry["expected_location"] or None
        item = conn.execute(
            "SELECT * FROM custody_items WHERE custody_number=?", (number,)
        ).fetchone()
        if item is None:
            reason = f"保管号 {number} 在保管库中查无对应实物（缺件）"
            return "missing", reason, None, self._entry_fingerprint(conn, case_id, entry)
        reg = conn.execute(
            "SELECT * FROM evidence WHERE case_id=? AND item_id=?", (case_id, item["id"])
        ).fetchone()
        if reg is None:
            reason = f"保管号 {number} 由其他案件入册，本案件无入册记录（缺件）"
            return "missing", reason, None, self._entry_fingerprint(conn, case_id, entry)
        actual = hashlib.sha256(item["content"]).hexdigest()
        if actual != item["sha256"]:
            reason = f"保管号 {number} 实物重算哈希 {actual[:16]}… 与入册摘要 {item['sha256'][:16]}… 不一致（损坏件）"
            return "damaged", reason, reg["id"], self._entry_fingerprint(conn, case_id, entry)
        if declared_sha and declared_sha.lower() != item["sha256"].lower():
            reason = (f"保管号 {number} 清单声明摘要 {declared_sha[:16]}… 与权威入册摘要 "
                      f"{item['sha256'][:16]}… 不一致（损坏件）")
            return "damaged", reason, reg["id"], self._entry_fingerprint(conn, case_id, entry)
        if reg["status"] == "released":
            reason = (f"保管号 {number} 已被本案件放行换出，接收方 "
                      f"{reg['release_recipient'] or '未登记'}，放行时间 {reg['released_at'] or '未记录'}（换出记录）")
            return "swapped_out", reason, reg["id"], self._entry_fingerprint(conn, case_id, entry)
        if declared_location and declared_location != item["current_location"]:
            reason = (f"保管号 {number} 当前位置 {item['current_location'] or '未记录'} "
                      f"与封存位置 {declared_location} 不一致（换出记录）")
            return "swapped_out", reason, reg["id"], self._entry_fingerprint(conn, case_id, entry)
        reason = (f"保管号 {number} 核验通过：{item['current_location'] or '在封'}，"
                  f"保管人 {item['current_custodian']}，链尖 {self._chain_tip(conn, item['id'])}")
        return "verified", reason, reg["id"], self._entry_fingerprint(conn, case_id, entry)

    def _sync_batch(self, conn, batch_id, limit=None):
        """作废指纹漂移的旧结果并重算待处理条目。

        每个条目的重算与落库都由 process_batch 放在独立事务里逐条提交，
        因此中断/异常只影响当前条目，已提交的处理进度保留，重放时从第一条
        pending 记录继续补全。

        返回 (漂移条数, 待处理条目id列表[受limit截断], 全部pending数)。
        """
        batch = conn.execute("SELECT * FROM archive_batches WHERE id=?", (batch_id,)).fetchone()
        if batch is None:
            raise BusinessError("封存清单不存在", 404, "not_found")
        drifted = 0
        for entry in conn.execute(
            "SELECT * FROM archive_entries WHERE batch_id=? AND status!='pending' ORDER BY id", (batch_id,)
        ).fetchall():
            current_fp = self._entry_fingerprint(conn, batch["case_id"], entry)
            if current_fp != entry["state_fingerprint"]:
                conn.execute(
                    """UPDATE archive_entries
                       SET status='pending', previous_status=status,
                           recompute_count=recompute_count+1, evidence_id=NULL
                     WHERE id=?""",
                    (entry["id"],),
                )
                drifted += 1
        if drifted:
            conn.execute(
                "UPDATE archive_batches SET recompute_count=recompute_count+1, status='processing' WHERE id=?",
                (batch_id,),
            )
        query = "SELECT id FROM archive_entries WHERE batch_id=? AND status='pending' ORDER BY id"
        params: list = [batch_id]
        if limit is not None:
            query += " LIMIT ?"
            params.append(max(0, limit))
        pending_ids = [r["id"] for r in conn.execute(query, params).fetchall()]
        total_pending = conn.execute(
            "SELECT COUNT(*) AS n FROM archive_entries WHERE batch_id=? AND status='pending'", (batch_id,)
        ).fetchone()["n"]
        return drifted, pending_ids, total_pending

    def _process_entry(self, batch, entry_id):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            entry = conn.execute("SELECT * FROM archive_entries WHERE id=?", (entry_id,)).fetchone()
            status, reason, evidence_id, fingerprint = self._evaluate_entry(conn, batch["case_id"], entry)
            conn.execute(
                """UPDATE archive_entries SET status=?,reason=?,evidence_id=?,state_fingerprint=?,processed_at=?
                   WHERE id=?""",
                (status, reason, evidence_id, fingerprint, now(), entry_id),
            )
            conn.commit()
            return status
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def process_batch(self, user_id, batch_id, limit=None, action="archive.process"):
        """对外的处理/重放入口，串行化并发 worker，每条目独立提交以支持断点续跑。"""
        with self.connect() as conn:
            batch = conn.execute("SELECT * FROM archive_batches WHERE id=?", (batch_id,)).fetchone()
            if batch is None:
                raise BusinessError("封存清单不存在", 404, "not_found")
            self._member(conn, batch["case_id"], user_id)
            case_id = batch["case_id"]
        with self._lock:
            conn = self.connect()
            total_drifted = 0
            try:
                conn.execute("BEGIN IMMEDIATE")
                drifted, pending_ids, total_pending = self._sync_batch(conn, batch_id, limit)
                if drifted:
                    total_drifted = drifted
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()
            processed = 0
            try:
                for entry_id in pending_ids:
                    self._process_entry(batch, entry_id)
                    processed += 1
            except Exception as exc:
                with self.connect() as err_conn:
                    err_conn.execute(
                        "UPDATE archive_batches SET status='failed',last_error=? WHERE id=?",
                        (f"处理条目 archive_entries#{entry_id} 中断: {exc}", batch_id),
                    )
                raise
            conn = self.connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                remaining = conn.execute(
                    "SELECT COUNT(*) AS n FROM archive_entries WHERE batch_id=? AND status='pending'",
                    (batch_id,),
                ).fetchone()["n"]
                final_status = "completed" if remaining == 0 else "processing"
                conn.execute(
                    "UPDATE archive_batches SET status=?,last_error='' WHERE id=?", (final_status, batch_id)
                )
                conn.commit()
            finally:
                conn.close()
            if processed or total_drifted:
                with self.connect() as audit_conn:
                    self._audit(audit_conn, case_id, user_id, action, {
                        "batch_id": batch_id, "processed": processed,
                        "recomputed": total_drifted, "limit": limit,
                    })
            return self.get_batch(user_id, batch_id, refresh=False)

    def _validate_entries(self, entries):
        if not isinstance(entries, list) or not entries:
            raise BusinessError("封存清单至少包含一条记录", 422, "invalid_manifest")
        clean, seen = [], set()
        for raw in entries:
            if not isinstance(raw, dict):
                raise BusinessError("清单条目必须是对象", 422, "invalid_manifest")
            number = str(raw.get("custody_number", "")).strip()
            if not number:
                raise BusinessError("清单条目缺少保管号", 422, "invalid_manifest")
            if number in seen:
                raise BusinessError(f"清单中保管号 {number} 重复", 422, "duplicate_entry")
            seen.add(number)
            clean.append({
                "custody_number": number,
                "expected_sha256": str(raw.get("expected_sha256") or "").strip(),
                "expected_location": str(raw.get("expected_location") or "").strip(),
            })
        return clean

    def submit_manifest(self, user_id, case_id, batch_number, stage, entries, initial_limit=None):
        """归档中间件提交封存清单。

        同一 batch_number 并发/重复提交时只有第一条落库，后续提交返回原清单并
        继续补全尚未处理的记录（幂等重放）。
        """
        batch_number, stage = str(batch_number or "").strip(), str(stage or "").strip()
        if not batch_number:
            raise BusinessError("清单批次号不能为空", 422, "invalid_manifest")
        if not stage:
            raise BusinessError("归档阶段不能为空", 422, "invalid_manifest")
        clean = self._validate_entries(entries)
        with self.connect() as conn:
            self._member(conn, case_id, user_id)
        duplicate = False
        with self._lock:
            conn = self.connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                existing = conn.execute(
                    "SELECT id FROM archive_batches WHERE batch_number=?", (batch_number,)
                ).fetchone()
                if existing is None:
                    cur = conn.execute(
                        """INSERT INTO archive_batches(batch_number,case_id,stage,status,submitted_by,submitted_at)
                           VALUES(?,?,?,'received',?,?)""",
                        (batch_number, case_id, stage, user_id, now()),
                    )
                    batch_id = cur.lastrowid
                    conn.executemany(
                        """INSERT INTO archive_entries(batch_id,custody_number,expected_sha256,expected_location)
                           VALUES(?,?,?,?)""",
                        [(batch_id, e["custody_number"], e["expected_sha256"], e["expected_location"])
                          for e in clean],
                    )
                    self._audit(conn, case_id, user_id, "archive.submit", {
                        "batch_number": batch_number, "stage": stage, "entries": len(clean),
                    })
                    conn.commit()
                else:
                    conn.rollback()
                    batch_id = existing["id"]
                    duplicate = True
            except Exception:
                conn.rollback()
                raise
        payload = self.process_batch(user_id, batch_id, limit=initial_limit, action="archive.process")
        if duplicate:
            payload["duplicate"] = True
            payload["message"] = "同一封存清单已提交过，仅保留第一条，本次仅补全未处理记录"
        return payload

    def replay_batch(self, user_id, batch_number):
        with self.connect() as conn:
            batch = conn.execute(
                "SELECT * FROM archive_batches WHERE batch_number=?", (batch_number,)
            ).fetchone()
            if batch is None:
                raise BusinessError("封存清单不存在", 404, "not_found")
            batch_id = batch["id"]
        return self.process_batch(user_id, batch_id, action="archive.replay")

    def _batch_payload(self, conn, batch):
        entries = [dict(e) | {"processed_at": e["processed_at"]} for e in conn.execute(
            "SELECT * FROM archive_entries WHERE batch_id=? ORDER BY id", (batch["id"],)
        ).fetchall()]
        totals = Counter(e["status"] for e in entries)
        return {
            "id": batch["id"], "batch_number": batch["batch_number"], "case_id": batch["case_id"],
            "stage": batch["stage"], "status": batch["status"],
            "submitted_by": batch["submitted_by"], "submitted_at": batch["submitted_at"],
            "recompute_count": batch["recompute_count"], "last_error": batch["last_error"],
            "total": len(entries),
            "counts": {s: totals.get(s, 0) for s in
                       ("pending", "verified", "missing", "damaged", "swapped_out")},
            "entries": entries,
        }

    def get_batch(self, user_id, batch_id, refresh=True):
        with self.connect() as conn:
            batch = conn.execute("SELECT * FROM archive_batches WHERE id=?", (batch_id,)).fetchone()
            if batch is None:
                raise BusinessError("封存清单不存在", 404, "not_found")
            self._member(conn, batch["case_id"], user_id)
        if refresh:
            # 查看即对账：权威状态一变，旧结论作废并立刻重算
            return self.process_batch(user_id, batch_id, action="archive.refresh")
        with self.connect() as conn:
            batch = conn.execute("SELECT * FROM archive_batches WHERE id=?", (batch_id,)).fetchone()
            return self._batch_payload(conn, batch)

    def list_batches(self, user_id, case_id):
        with self.connect() as conn:
            self._member(conn, case_id, user_id)
            rows = conn.execute(
                "SELECT * FROM archive_batches WHERE case_id=? ORDER BY id", (case_id,)
            ).fetchall()
            result = []
            for b in rows:
                totals = Counter(r["status"] for r in conn.execute(
                    "SELECT status FROM archive_entries WHERE batch_id=?", (b["id"],)
                ).fetchall())
                result.append({
                    "id": b["id"], "batch_number": b["batch_number"], "stage": b["stage"],
                    "status": b["status"], "submitted_by": b["submitted_by"],
                    "submitted_at": b["submitted_at"], "recompute_count": b["recompute_count"],
                    "last_error": b["last_error"],
                    "counts": {s: totals.get(s, 0) for s in
                               ("pending", "verified", "missing", "damaged", "swapped_out")},
                })
            return {"case_id": case_id, "batch_count": len(result), "batches": result}

    # ------------------------------------------------------------------
    # 报告
    # ------------------------------------------------------------------

    def report(self, user_id, case_id):
        with self.connect() as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                self._member(conn, case_id, user_id)
                case = self._case(conn, case_id)
                child_parents = {
                    r["child_evidence_id"]: (r["parent_evidence_id"], r["method"])
                    for r in conn.execute(
                        """SELECT d.child_evidence_id,d.parent_evidence_id,d.method
                           FROM derivatives d JOIN evidence e ON e.id=d.child_evidence_id
                           WHERE e.case_id=?""",
                        (case_id,),
                    ).fetchall()
                }
                items, all_valid = [], True
                rows = conn.execute(
                    "SELECT * FROM evidence WHERE case_id=? ORDER BY id", (case_id,)
                ).fetchall()
                for row in rows:
                    item = conn.execute(
                        "SELECT * FROM custody_items WHERE id=?", (row["item_id"],)
                    ).fetchone()
                    hash_valid = hashlib.sha256(item["content"]).hexdigest() == item["sha256"]
                    chain_valid, events = self._verify_chain(conn, item["id"])
                    all_valid = all_valid and hash_valid and chain_valid
                    children = conn.execute(
                        "SELECT * FROM derivatives WHERE parent_evidence_id=? ORDER BY id", (row["id"],)
                    ).fetchall()
                    parent_info = child_parents.get(row["id"])
                    other_cases = conn.execute(
                        """SELECT e.id AS evidence_id,e.case_id,c.case_number,e.label,e.status,e.legal_hold
                           FROM evidence e JOIN cases c ON c.id=e.case_id
                           WHERE e.item_id=? AND e.case_id!=? ORDER BY e.id""",
                        (item["id"], case_id),
                    ).fetchall()
                    items.append({
                        "id": row["id"], "item_id": item["id"], "custody_number": item["custody_number"],
                        "label": row["label"], "filename": item["filename"],
                        "sha256": item["sha256"], "size": item["size"],
                        "status": row["status"], "legal_hold": bool(row["legal_hold"]),
                        "retention_until": row["retention_until"],
                        "release_recipient": row["release_recipient"], "released_at": row["released_at"],
                        "physical_status": item["physical_status"],
                        "current_custodian": item["current_custodian"],
                        "current_location": item["current_location"],
                        "hash_valid": hash_valid, "chain_valid": chain_valid,
                        "is_parent": len(children) > 0,
                        "parent_evidence_id": None if parent_info is None else parent_info[0],
                        "derive_method": None if parent_info is None else parent_info[1],
                        "child_evidence_ids": [c["child_evidence_id"] for c in children],
                        "cross_case_reuse": {
                            "reused_here": item["first_case_id"] != case_id,
                            "origin_case_id": item["first_case_id"],
                            "other_registrations": [
                                dict(r) | {"legal_hold": bool(r["legal_hold"])} for r in other_cases
                            ],
                        },
                        "events": events,
                        "derivatives": [dict(c) for c in children],
                    })
                # 归档批次：随报告一起作废重算，输出最新核验/重算结果
                archive = []
                for b in conn.execute(
                    "SELECT * FROM archive_batches WHERE case_id=? ORDER BY id", (case_id,)
                ).fetchall():
                    _, pending_ids, _ = self._sync_batch(conn, b["id"])
                    for entry_id in pending_ids:
                        entry = conn.execute(
                            "SELECT * FROM archive_entries WHERE id=?", (entry_id,)
                        ).fetchone()
                        status, reason, evidence_id, fingerprint = self._evaluate_entry(
                            conn, case_id, entry
                        )
                        conn.execute(
                            """UPDATE archive_entries
                               SET status=?,reason=?,evidence_id=?,state_fingerprint=?,processed_at=?
                               WHERE id=?""",
                            (status, reason, evidence_id, fingerprint, now(), entry_id),
                        )
                    remaining = conn.execute(
                        "SELECT COUNT(*) AS n FROM archive_entries WHERE batch_id=? AND status='pending'",
                        (b["id"],),
                    ).fetchone()["n"]
                    conn.execute(
                        "UPDATE archive_batches SET status=?,last_error='' WHERE id=?",
                        ("completed" if remaining == 0 else "processing", b["id"]),
                    )
                    archive.append(self._batch_payload(
                        conn,
                        conn.execute("SELECT * FROM archive_batches WHERE id=?", (b["id"],)).fetchone(),
                    ))
                audit = conn.execute(
                    "SELECT * FROM audit_log WHERE case_id=? ORDER BY id", (case_id,)
                ).fetchall()
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            return {
                "case": dict(case), "generated_at": now(), "overall_integrity_valid": all_valid,
                "evidence_count": len(items),
                "parent_child_links": [
                    {"parent_evidence_id": pid, "child_evidence_id": cid, "method": method}
                    for cid, (pid, method) in child_parents.items()
                ],
                "evidence": items,
                "archive": {
                    "batch_count": len(archive),
                    "recomputed_total": sum(b["recompute_count"] for b in archive),
                    "missing_total": sum(b["counts"]["missing"] for b in archive),
                    "damaged_total": sum(b["counts"]["damaged"] for b in archive),
                    "swapped_out_total": sum(b["counts"]["swapped_out"] for b in archive),
                    "batches": archive,
                },
                "audit": [dict(a) | {"detail": json.loads(a["detail"])} for a in audit],
            }


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
        # 归档封存清单
        if len(parts)==5 and parts[:2]==["api","cases"] and parts[3:5]==["archive","batches"]:
            case_id=int(parts[2])
            if method=="GET": return self._send(200,store.list_batches(user,case_id))
            if method=="POST":
                d=self._body()
                limit=d.get("initial_limit")
                if limit is not None:
                    try: limit=max(0,int(limit))
                    except (ValueError,TypeError): limit=None
                payload=store.submit_manifest(user,case_id,d.get("batch_number",""),d.get("stage",""),d.get("entries",[]),initial_limit=limit)
                return self._send(201 if not payload.get("duplicate") else 200,payload)
        if len(parts)==4 and parts[:3]==["api","archive","batches"] and method=="GET":
            return self._send(200,store.get_batch(user,int(parts[3])))
        if len(parts)==5 and parts[:3]==["api","archive","batches"] and parts[4]=="replay" and method=="POST":
            return self._send(200,store.replay_batch(user,parts[3]))
        if len(parts)>=3 and parts[:2]==["api","evidence"]:
            evidence_id=int(parts[2])
            if len(parts)==3 and method=="GET": return self._send(200,store.get_evidence(user,evidence_id,bool(urlparse(self.path).query)))
            if len(parts)==4 and method=="POST":
                d=self._body()
                if parts[3]=="transfer": return self._send(200,store.transfer(user,evidence_id,d.get("to_person",""),d.get("location",""),d.get("note","")))
                if parts[3]=="open": return self._send(200,store.open_evidence(user,evidence_id,d.get("location",""),d.get("note","")))
                if parts[3]=="derive": return self._send(201,store.derive(user,evidence_id,d.get("method",""),d.get("label",""),d.get("filename",""),d.get("content_b64","")))
                if parts[3]=="release": return self._send(200,store.release(user,evidence_id,d.get("recipient",""),d.get("note","")))
                if parts[3]=="hold": return self._send(200,store.set_hold(user,evidence_id,bool(d.get("hold")),d.get("reason","")))
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
