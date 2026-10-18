"""SQLite storage: settings, sessions, Telegram accounts, the file tree and chunk map.

The tree lives here; file contents live in Telegram as encrypted chunks. Each file
node points at a content id (cid). Copies share a cid, so copying is instant and
costs no upload; a cid's messages are deleted only when no node uses it any more.
"""
from __future__ import annotations

import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Optional

ROOT = "root"

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS tg_accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tg_user_id INTEGER NOT NULL UNIQUE,
    phone TEXT NOT NULL,
    name TEXT NOT NULL,
    label TEXT NOT NULL,
    session TEXT NOT NULL,
    created REAL NOT NULL,
    disabled INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS nodes (
    id TEXT PRIMARY KEY,
    parent TEXT,
    name TEXT NOT NULL,
    is_dir INTEGER NOT NULL,
    cid TEXT,
    size INTEGER NOT NULL DEFAULT 0,
    mime TEXT NOT NULL DEFAULT 'application/octet-stream',
    created REAL NOT NULL,
    modified REAL NOT NULL,
    UNIQUE (parent, name)
);
CREATE INDEX IF NOT EXISTS nodes_cid ON nodes(cid);
CREATE TABLE IF NOT EXISTS chunks (
    cid TEXT NOT NULL,
    idx INTEGER NOT NULL,
    account_id INTEGER NOT NULL,
    message_id INTEGER NOT NULL,
    plain_size INTEGER NOT NULL,
    stored_size INTEGER NOT NULL,
    prefix BLOB NOT NULL,
    PRIMARY KEY (cid, idx)
);
CREATE INDEX IF NOT EXISTS chunks_account ON chunks(account_id);
CREATE TABLE IF NOT EXISTS retired_accounts (
    id INTEGER PRIMARY KEY,
    tg_user_id INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS delete_queue (
    account_id INTEGER NOT NULL,
    message_id INTEGER NOT NULL,
    not_before REAL NOT NULL DEFAULT 0,
    PRIMARY KEY (account_id, message_id)
);
CREATE TABLE IF NOT EXISTS shares (
    token_hash TEXT PRIMARY KEY,
    node_id TEXT NOT NULL,
    created REAL NOT NULL,
    expires REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    created REAL NOT NULL,
    expires REAL NOT NULL,
    user_agent TEXT
);
CREATE TABLE IF NOT EXISTS dav_props (
    path TEXT NOT NULL,
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (path, name)
);
CREATE TABLE IF NOT EXISTS app_passwords (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    hash TEXT NOT NULL UNIQUE,
    created REAL NOT NULL,
    last_used REAL
);
"""


class Store:
    def __init__(self, path: Path | str):
        self._db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA foreign_keys=ON")
        self._lock = threading.RLock()
        self._in_tx = False
        with self._lock:
            self._db.executescript(SCHEMA)
            now = time.time()
            self._db.execute("INSERT OR IGNORE INTO nodes(id,parent,name,is_dir,created,modified) "
                             "VALUES(?,NULL,'',1,?,?)", (ROOT, now, now))

    def _exec(self, sql: str, args: tuple = ()) -> sqlite3.Cursor:
        with self._lock:
            return self._db.execute(sql, args)

    @contextmanager
    def tx(self) -> Iterator[None]:
        """All-or-nothing group of writes (re-entrant)."""
        with self._lock:
            if self._in_tx:
                yield
                return
            self._db.execute("BEGIN IMMEDIATE")
            self._in_tx = True
            try:
                yield
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
            finally:
                self._in_tx = False

    def close(self) -> None:
        self._db.close()

    # settings
    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        row = self._exec("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default

    def set(self, key: str, value: Optional[str]) -> None:
        if value is None:
            self._exec("DELETE FROM settings WHERE key=?", (key,))
        else:
            self._exec("INSERT INTO settings(key,value) VALUES(?,?) "
                       "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))

    # Telegram accounts
    def accounts(self, include_disabled: bool = True) -> list[dict[str, Any]]:
        sql = "SELECT * FROM tg_accounts" + ("" if include_disabled else " WHERE disabled=0")
        return [dict(r) for r in self._exec(sql + " ORDER BY id")]

    def account(self, account_id: int) -> Optional[dict[str, Any]]:
        row = self._exec("SELECT * FROM tg_accounts WHERE id=?", (account_id,)).fetchone()
        return dict(row) if row else None

    def upsert_account(self, tg_user_id: int, phone: str, name: str, label: str,
                       session: str) -> int:
        row = self._exec("SELECT id FROM tg_accounts WHERE tg_user_id=?", (tg_user_id,)).fetchone()
        if row:
            self._exec("UPDATE tg_accounts SET session=?, phone=?, name=?, disabled=0 WHERE id=?",
                       (session, phone, name, row["id"]))
            return row["id"]
        with self.tx():
            new_id = self._exec("INSERT INTO tg_accounts(tg_user_id,phone,name,label,session,created) "
                                "VALUES(?,?,?,?,?,?)",
                                (tg_user_id, phone, name, label, session, time.time())).lastrowid
            # parts left behind by an earlier, force-unlinked link of the same Telegram account
            old = "SELECT id FROM retired_accounts WHERE tg_user_id=?"
            self._exec(f"UPDATE chunks SET account_id=? WHERE account_id IN ({old})",
                       (new_id, tg_user_id))
            self._exec(f"UPDATE delete_queue SET account_id=? WHERE account_id IN ({old})",
                       (new_id, tg_user_id))
            self._exec("DELETE FROM retired_accounts WHERE tg_user_id=?", (tg_user_id,))
        return new_id

    def rename_account(self, account_id: int, label: str) -> bool:
        return self._exec("UPDATE tg_accounts SET label=? WHERE id=?", (label, account_id)).rowcount > 0

    def delete_account(self, account_id: int) -> bool:
        with self.tx():
            row = self._exec("SELECT tg_user_id FROM tg_accounts WHERE id=?", (account_id,)).fetchone()
            if row is None:
                return False
            if self._exec("SELECT 1 FROM chunks WHERE account_id=? LIMIT 1", (account_id,)).fetchone():
                self._exec("INSERT OR REPLACE INTO retired_accounts VALUES(?,?)",
                           (account_id, row["tg_user_id"]))
            self._exec("DELETE FROM tg_accounts WHERE id=?", (account_id,))
        return True

    def account_usage(self) -> dict[int, tuple[int, int]]:
        """account_id -> (stored bytes, number of parts)."""
        return {r["account_id"]: (r["b"], r["n"]) for r in self._exec(
            "SELECT account_id, COALESCE(SUM(stored_size),0) b, COUNT(*) n FROM chunks "
            "GROUP BY account_id")}

    # tree
    def node(self, node_id: str) -> Optional[dict[str, Any]]:
        row = self._exec("SELECT * FROM nodes WHERE id=?", (node_id,)).fetchone()
        return dict(row) if row else None

    def child(self, parent: str, name: str) -> Optional[dict[str, Any]]:
        row = self._exec("SELECT * FROM nodes WHERE parent=? AND name=?", (parent, name)).fetchone()
        return dict(row) if row else None

    def children(self, parent: str) -> list[dict[str, Any]]:
        return [dict(r) for r in self._exec(
            "SELECT * FROM nodes WHERE parent=? ORDER BY is_dir DESC, name COLLATE NOCASE", (parent,))]

    def insert_node(self, node: dict[str, Any]) -> None:
        self._exec("INSERT INTO nodes(id,parent,name,is_dir,cid,size,mime,created,modified) "
                   "VALUES(:id,:parent,:name,:is_dir,:cid,:size,:mime,:created,:modified)", node)

    def update_node(self, node_id: str, **fields: Any) -> None:
        cols = ", ".join(f"{k}=:{k}" for k in fields)
        self._exec(f"UPDATE nodes SET {cols} WHERE id=:id", {**fields, "id": node_id})

    def subtree(self, node_id: str) -> list[dict[str, Any]]:
        return [dict(r) for r in self._exec(
            "WITH RECURSIVE t(id) AS (SELECT ? UNION ALL SELECT n.id FROM nodes n JOIN t ON n.parent=t.id) "
            "SELECT nodes.* FROM nodes JOIN t ON nodes.id=t.id", (node_id,))]

    def delete_nodes(self, ids: list[str]) -> None:
        for i in range(0, len(ids), 500):
            part = ids[i:i + 500]
            self._exec(f"DELETE FROM nodes WHERE id IN ({','.join('?' * len(part))})", tuple(part))

    def cid_in_use(self, cid: str) -> bool:
        return self._exec("SELECT 1 FROM nodes WHERE cid=? LIMIT 1", (cid,)).fetchone() is not None

    def node_by_cid(self, cid: str) -> Optional[dict[str, Any]]:
        row = self._exec("SELECT * FROM nodes WHERE cid=? LIMIT 1", (cid,)).fetchone()
        return dict(row) if row else None

    def all_nodes(self) -> list[dict[str, Any]]:
        return [dict(r) for r in self._exec("SELECT * FROM nodes")]

    def search(self, text: str, limit: int) -> list[dict[str, Any]]:
        like = "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        return [dict(r) for r in self._exec(
            "SELECT * FROM nodes WHERE id != ? AND name LIKE ? ESCAPE '\\' "
            "ORDER BY is_dir DESC, name COLLATE NOCASE LIMIT ?", (ROOT, like, limit))]

    def path_of(self, node_id: str) -> Optional[str]:
        parts, cur, seen = [], node_id, set()
        while cur and cur != ROOT:
            if cur in seen:
                return None
            seen.add(cur)
            n = self.node(cur)
            if n is None:
                return None
            parts.append(n["name"])
            cur = n["parent"]
        return "/" + "/".join(reversed(parts))

    def total_size(self) -> int:
        return self._exec("SELECT COALESCE(SUM(size),0) FROM nodes WHERE is_dir=0").fetchone()[0]

    # chunks
    def chunks(self, cid: str) -> list[dict[str, Any]]:
        return [dict(r) for r in self._exec("SELECT * FROM chunks WHERE cid=? ORDER BY idx", (cid,))]

    def insert_chunk(self, c: dict[str, Any]) -> None:
        self._exec("INSERT OR REPLACE INTO chunks(cid,idx,account_id,message_id,plain_size,stored_size,prefix) "
                   "VALUES(:cid,:idx,:account_id,:message_id,:plain_size,:stored_size,:prefix)", c)

    def delete_chunks(self, cid: str) -> list[dict[str, Any]]:
        rows = self.chunks(cid)
        self._exec("DELETE FROM chunks WHERE cid=?", (cid,))
        return rows

    def all_chunks(self) -> list[dict[str, Any]]:
        return [dict(r) for r in self._exec("SELECT * FROM chunks")]

    def known_messages(self, account_id: int) -> set[int]:
        return {r[0] for r in self._exec("SELECT message_id FROM chunks WHERE account_id=?", (account_id,))}

    # deferred Telegram deletes (when an account was unreachable)
    def queue_delete(self, account_id: int, message_ids: list[int], not_before: float = 0) -> None:
        for mid in message_ids:
            self._exec("INSERT OR IGNORE INTO delete_queue(account_id,message_id,not_before) "
                       "VALUES(?,?,?)", (account_id, mid, not_before))

    def pending_deletes(self) -> dict[int, list[int]]:
        out: dict[int, list[int]] = {}
        for r in self._exec("SELECT * FROM delete_queue WHERE not_before <= ?", (time.time(),)):
            out.setdefault(r["account_id"], []).append(r["message_id"])
        return out

    def clear_deletes(self, account_id: int, message_ids: list[int]) -> None:
        for mid in message_ids:
            self._exec("DELETE FROM delete_queue WHERE account_id=? AND message_id=?", (account_id, mid))

    # share links
    def add_share(self, token_hash: str, node_id: str, expires: float) -> None:
        self._exec("INSERT INTO shares VALUES(?,?,?,?)", (token_hash, node_id, time.time(), expires))

    def share(self, token_hash: str) -> Optional[dict[str, Any]]:
        row = self._exec("SELECT * FROM shares WHERE token_hash=? AND expires > ?",
                         (token_hash, time.time())).fetchone()
        return dict(row) if row else None

    def shares(self) -> list[dict[str, Any]]:
        return [dict(r) for r in self._exec(
            "SELECT * FROM shares WHERE expires > ? ORDER BY created DESC", (time.time(),))]

    def delete_share(self, token_hash: str) -> bool:
        return self._exec("DELETE FROM shares WHERE token_hash=?", (token_hash,)).rowcount > 0

    # sessions
    def create_session(self, sid_hash: str, days: int, user_agent: str = "") -> None:
        now = time.time()
        self._exec("INSERT INTO sessions(id,created,expires,user_agent) VALUES(?,?,?,?)",
                   (sid_hash, now, now + days * 86400, user_agent[:200]))

    def session_valid(self, sid_hash: str) -> bool:
        row = self._exec("SELECT expires FROM sessions WHERE id=?", (sid_hash,)).fetchone()
        return bool(row and row["expires"] > time.time())

    def delete_session(self, sid_hash: str) -> None:
        self._exec("DELETE FROM sessions WHERE id=?", (sid_hash,))

    def delete_all_sessions(self) -> None:
        self._exec("DELETE FROM sessions")

    def purge_expired_sessions(self) -> None:
        self._exec("DELETE FROM sessions WHERE expires < ?", (time.time(),))

    # app passwords (for WebDAV)
    def add_app_password(self, name: str, hashed: str) -> int:
        return self._exec("INSERT INTO app_passwords(name,hash,created) VALUES(?,?,?)",
                          (name, hashed, time.time())).lastrowid

    def app_passwords(self) -> list[dict[str, Any]]:
        return [dict(r) for r in self._exec(
            "SELECT id,name,created,last_used FROM app_passwords ORDER BY id")]

    def app_password_by_hash(self, hashed: str) -> Optional[int]:
        row = self._exec("SELECT id FROM app_passwords WHERE hash=?", (hashed,)).fetchone()
        if row:
            self._exec("UPDATE app_passwords SET last_used=? WHERE id=?", (time.time(), row["id"]))
            return row["id"]
        return None

    def delete_app_password(self, pid: int) -> bool:
        return self._exec("DELETE FROM app_passwords WHERE id=?", (pid,)).rowcount > 0

    # WebDAV dead properties (e.g. Windows file times), keyed by unified path
    def props(self, path: str) -> dict[str, str]:
        return {r["name"]: r["value"] for r in self._exec(
            "SELECT name, value FROM dav_props WHERE path=?", (path,))}

    def set_props(self, path: str, updates: dict[str, Optional[str]]) -> None:
        with self._lock:
            self._db.execute("BEGIN")
            try:
                for name, value in updates.items():
                    if value is None:
                        self._db.execute("DELETE FROM dav_props WHERE path=? AND name=?", (path, name))
                    else:
                        self._db.execute("INSERT INTO dav_props(path,name,value) VALUES(?,?,?) "
                                         "ON CONFLICT(path,name) DO UPDATE SET value=excluded.value",
                                         (path, name, value))
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    @staticmethod
    def _like(path: str) -> str:
        return path.rstrip("/").replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "/%"

    def delete_props(self, path: str) -> None:
        self._exec("DELETE FROM dav_props WHERE path=? OR path LIKE ? ESCAPE '\\'",
                   (path, self._like(path)))

    def copy_props(self, src: str, dst: str, move: bool = False) -> None:
        rows = self._exec("SELECT path, name, value FROM dav_props WHERE path=? OR path LIKE ? ESCAPE '\\'",
                          (src, self._like(src))).fetchall()
        self.delete_props(dst)
        for r in rows:
            new = dst + r["path"][len(src):]
            self._exec("INSERT OR REPLACE INTO dav_props(path,name,value) VALUES(?,?,?)",
                       (new, r["name"], r["value"]))
        if move:
            self.delete_props(src)
