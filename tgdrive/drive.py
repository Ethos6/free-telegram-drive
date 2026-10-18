"""The drive: a folder tree whose files are encrypted chunks in Telegram Saved Messages.

* Files are split into chunks (default 256 MiB, below Telegram's 2 GB limit),
  encrypted with AES-256-GCM (see crypto.py) and uploaded as documents to the
  Saved Messages of the linked accounts, spread across accounts so large files
  upload and download in parallel.
* Every chunk's caption carries encrypted metadata, and an encrypted snapshot of
  the whole index is kept in Saved Messages, so the tree can be rebuilt on a new
  server from the recovery key and the Telegram accounts alone.
* Copies share content (instant, no upload); content is deleted from Telegram
  only when no file uses it any more.
"""
from __future__ import annotations

import asyncio
import base64
import io
import json
import logging
import mimetypes
import os
import secrets
import sqlite3
import tempfile
import time
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, AsyncIterator, BinaryIO, Callable, Optional

from . import crypto
from .store import ROOT, Store
from .telegram import TelegramAPI, TelegramError

log = logging.getLogger("tgdrive")

TAG_CHUNK = "tgdrive:c1:"
TAG_INDEX = "tgdrive:i1:"
MAX_CAPTION = 1000
DEFAULT_CHUNK = 256 * 1024 * 1024
UNLIMITED = 1 << 50  # what WebDAV clients are told is free (1 PiB)
KEEP_SNAPSHOTS = 3
GC_GRACE = 6 * 3600  # seconds to keep content that was being downloaded when deleted


class DriveError(Exception):
    def __init__(self, message: str, status: int):
        super().__init__(message)
        self.status = status


def split(path: str) -> list[str]:
    parts = [p for p in (path or "").replace("\\", "/").split("/") if p]
    if any(p in (".", "..") for p in parts):
        raise DriveError("invalid path", 400)
    return parts


def join(parts: list[str]) -> str:
    return "/" + "/".join(parts)


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


@dataclass
class Entry:
    id: str
    name: str
    path: str
    is_dir: bool
    size: Optional[int]
    modified: str
    mime: str
    etag: str
    accounts: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "path": self.path, "is_dir": self.is_dir, "size": self.size,
                "modified": self.modified, "mime": self.mime, "accounts": self.accounts}


@dataclass
class Quota:
    used: int
    total: Optional[int]

    @property
    def free(self) -> int:
        return UNLIMITED if self.total is None else max(0, self.total - self.used)


@dataclass
class Download:
    chunks: AsyncIterator[bytes]
    size: int
    mime: str
    status: int = 200
    content_range: Optional[str] = None

    async def aclose(self) -> None:
        await self.chunks.aclose()  # type: ignore[attr-defined]


def parse_range(header: Optional[str], size: int) -> Optional[tuple[int, int]]:
    """(start, end) inclusive for a single 'bytes=' range, None for the whole file."""
    if not header or not header.startswith("bytes=") or "," in header:
        return None
    a, _, b = header[6:].strip().partition("-")
    try:
        if a == "":
            n = int(b)
            if n <= 0:
                return None
            return max(0, size - n), size - 1
        start = int(a)
        end = int(b) if b else size - 1
    except ValueError:
        return None
    if end < start:
        return None  # syntactically invalid: ignore the header (RFC 9110 14.2)
    if start >= size:
        raise DriveError("range not satisfiable", 416)
    return start, min(end, size - 1)


class Drive:
    def __init__(self, store: Store, tg: TelegramAPI, chunk_size: int = DEFAULT_CHUNK,
                 parallel: int = 3, snapshot_delay: float = 20):
        self.store, self.tg = store, tg
        self.chunk_size, self.parallel, self.snapshot_delay = chunk_size, parallel, snapshot_delay
        self.master: Optional[bytes] = None
        self.errors: dict[int, str] = {}
        self._readers: dict[str, int] = {}
        self._dirty_since: Optional[float] = None
        self._snap_lock = asyncio.Lock()
        self._bg: Optional[asyncio.Task] = None

    # -- setup ----------------------------------------------------------------------------
    def unlock(self, master: bytes) -> None:
        self.master = master

    def _key(self) -> bytes:
        if self.master is None:
            raise DriveError("the vault is not set up yet", 409)
        return self.master

    def active_accounts(self) -> list[dict[str, Any]]:
        return [a for a in self.store.accounts(include_disabled=False) if a["id"] not in self.errors]

    def label(self, account_id: int) -> str:
        acc = self.store.account(account_id)
        return acc["label"] if acc else f"account {account_id}"

    def start_background(self) -> None:
        if self._bg is None:
            self._bg = asyncio.create_task(self._background())

    async def stop_background(self) -> None:
        if self._bg is not None:
            self._bg.cancel()
            try:
                await self._bg
            except (asyncio.CancelledError, Exception):
                pass
            self._bg = None

    async def _background(self) -> None:
        while True:
            await asyncio.sleep(2)
            try:
                if self._dirty_since and time.time() - self._dirty_since >= self.snapshot_delay:
                    await self.snapshot()
                await self.flush_deletes()
            except asyncio.CancelledError:
                raise
            except Exception as e:  # keep going; the next change retries
                log.warning("background task: %s", e)

    def _changed(self) -> None:
        if self._dirty_since is None:
            self._dirty_since = time.time()

    # -- tree ------------------------------------------------------------------------------
    def _resolve(self, parts: list[str]) -> Optional[dict[str, Any]]:
        node = self.store.node(ROOT)
        for p in parts:
            node = self.store.child(node["id"], p)
            if node is None:
                return None
        return node

    def _entry(self, node: dict[str, Any], path: str) -> Entry:
        accounts: list[str] = []
        if not node["is_dir"] and node["cid"]:
            ids = sorted({c["account_id"] for c in self.store.chunks(node["cid"])})
            accounts = [self.label(i) for i in ids]
        etag = (node["cid"] or node["id"])[:16] + f"-{node['size']}"
        return Entry(node["id"], node["name"], path, bool(node["is_dir"]),
                     None if node["is_dir"] else node["size"], _iso(node["modified"]),
                     node["mime"], etag, accounts)

    async def ls(self, path: str) -> list[Entry]:
        parts = split(path)
        node = self._resolve(parts)
        if node is None or not node["is_dir"]:
            raise DriveError("folder not found", 404)
        return [self._entry(c, join(parts + [c["name"]])) for c in self.store.children(node["id"])]

    async def stat(self, path: str) -> Entry:
        parts = split(path)
        node = self._resolve(parts)
        if node is None:
            raise DriveError("not found", 404)
        return self._entry(node, join(parts))

    async def exists(self, path: str) -> bool:
        return self._resolve(split(path)) is not None

    def _parent(self, parts: list[str]) -> dict[str, Any]:
        if not parts:
            raise DriveError("invalid path", 400)
        parent = self._resolve(parts[:-1])
        if parent is None:
            raise DriveError("parent folder not found", 404)
        if not parent["is_dir"]:
            raise DriveError("parent is not a folder", 409)
        return parent

    def _check_name(self, name: str) -> str:
        if (len(name) > 255 or name in (".", "..") or "\\" in name
                or any(ord(ch) < 32 for ch in name)):
            raise DriveError("invalid name", 400)
        return name

    async def mkdir(self, path: str) -> Entry:
        parts = split(path)
        parent = self._parent(parts)
        if self.store.child(parent["id"], parts[-1]):
            raise DriveError("already exists", 405)
        now = time.time()
        self.store.insert_node({"id": secrets.token_hex(12), "parent": parent["id"],
                                "name": self._check_name(parts[-1]), "is_dir": 1, "cid": None,
                                "size": 0, "mime": "inode/directory", "created": now,
                                "modified": now})
        self._changed()
        return await self.stat(path)

    async def makedirs(self, path: str) -> None:
        parts = split(path)
        for i in range(1, len(parts) + 1):
            if not await self.exists(join(parts[:i])):
                await self.mkdir(join(parts[:i]))

    async def quotas(self) -> list[tuple[None, Quota]]:
        return [(None, Quota(self.store.total_size(), None))]

    async def search(self, text: str, limit: int = 200) -> list[dict[str, Any]]:
        text = text.strip()
        if not text:
            return []
        out = []
        for n in self.store.search(text, limit):
            path = self.store.path_of(n["id"])
            if path is None:
                continue
            e = self._entry(n, path)
            d = e.to_dict()
            d["folder"] = path.rsplit("/", 1)[0] or "/"
            out.append(d)
        return out

    # -- upload ------------------------------------------------------------------------------
    def _caption(self, meta: dict[str, Any]) -> str:
        for _ in range(24):
            raw = json.dumps(meta, separators=(",", ":"), ensure_ascii=False).encode()
            caption = TAG_CHUNK + _b64(crypto.seal_blob(self._key(), "caption", raw))
            if len(caption) <= MAX_CAPTION:
                return caption
            # the caption only helps a rebuild find the name; shorten path first, then name
            if meta.get("pa"):
                meta["pa"] = meta["pa"][: len(meta["pa"]) // 2]
            else:
                meta["nm"] = meta.get("nm", "")[: len(meta.get("nm", "")) // 2]
        raise DriveError("file name too long", 400)

    def _plan(self, n: int) -> list[int]:
        """Spread n chunks over the healthy accounts, least-used first."""
        accounts = self.active_accounts()
        if not accounts:
            raise DriveError("no Telegram account is linked and reachable", 503)
        usage = self.store.account_usage()
        accounts.sort(key=lambda a: usage.get(a["id"], (0, 0))[0])
        return [accounts[i % len(accounts)]["id"] for i in range(n)]

    async def write(self, path: str, src: BinaryIO, size: int,
                    mime: Optional[str] = None,
                    progress: Optional[Callable[[int], None]] = None) -> Entry:
        parts = split(path)
        parent = self._parent(parts)
        name = self._check_name(parts[-1])
        existing = self.store.child(parent["id"], name)
        if existing and existing["is_dir"]:
            raise DriveError("a folder with that name exists", 409)
        mime = mime or mimetypes.guess_type(name)[0] or "application/octet-stream"
        key = self._key()
        cid = secrets.token_hex(16)
        fkey = crypto.file_key(key, cid)
        n = -(-size // self.chunk_size) if size else 0
        plan = self._plan(n)
        src_lock = asyncio.Lock()
        sem = asyncio.Semaphore(self.parallel)
        done: list[dict[str, Any]] = []
        sent = [0]

        async def one(idx: int) -> None:
            async with sem:
                plain = min(self.chunk_size, size - idx * self.chunk_size)
                prefix = os.urandom(8)
                with tempfile.SpooledTemporaryFile(max_size=64 * 1024 * 1024) as buf:
                    async with src_lock:
                        def enc() -> int:
                            src.seek(idx * self.chunk_size)
                            return crypto.encrypt_chunk(fkey, cid, idx, prefix, src, plain, buf)
                        stored = await asyncio.to_thread(enc)
                    meta = {"c": cid, "i": idx, "n": n, "s": size, "ps": plain, "p": _b64(prefix),
                            "m": mime, "nm": name[:150], "pa": join(parts[:-1])[:300]}
                    caption = self._caption(meta)
                    account = plan[idx]
                    for attempt in range(3):
                        try:
                            mid = await self.tg.upload(account, buf, stored,
                                                       f"{cid[:12]}.{idx:05d}.bin", caption)
                            break
                        except TelegramError as e:
                            if e.status < 429 or attempt == 2:
                                if e.status == 401:
                                    self.errors[account] = str(e)
                                raise
                            await asyncio.sleep(2 ** attempt)
                done.append({"cid": cid, "idx": idx, "account_id": account, "message_id": mid,
                             "plain_size": plain, "stored_size": stored, "prefix": prefix})
                sent[0] += plain
                if progress:
                    progress(sent[0])

        tasks = [asyncio.ensure_future(one(i)) for i in range(n)]
        try:
            await asyncio.gather(*tasks)
        except BaseException as e:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await self._discard(done)
            if isinstance(e, TelegramError):
                raise DriveError(f"upload to Telegram failed: {e}", e.status if e.status >= 400 else 502) from e
            raise
        now = time.time()
        old_cid = None
        try:
            with self.store.tx():
                if self.store.node(parent["id"]) is None:
                    raise DriveError("the folder was deleted during the upload", 409)
                current = self.store.child(parent["id"], name)
                if current and current["is_dir"]:
                    raise DriveError("a folder with that name exists", 409)
                for c in done:
                    self.store.insert_chunk(c)
                if current:
                    old_cid = current["cid"]
                    self.store.update_node(current["id"], cid=cid, size=size, mime=mime,
                                           modified=now)
                else:
                    self.store.insert_node({"id": secrets.token_hex(12), "parent": parent["id"],
                                            "name": name, "is_dir": 0, "cid": cid, "size": size,
                                            "mime": mime, "created": now, "modified": now})
        except (DriveError, sqlite3.IntegrityError) as e:
            await self._discard(done)
            if isinstance(e, DriveError):
                raise
            raise DriveError("something else was saved at this path at the same time", 409) from e
        if old_cid:
            await self._gc([old_cid])
        self._changed()
        return await self.stat(path)

    async def _discard(self, chunks: list[dict[str, Any]]) -> None:
        by_acc: dict[int, list[int]] = {}
        for c in chunks:
            by_acc.setdefault(c["account_id"], []).append(c["message_id"])
        for acc, mids in by_acc.items():
            try:
                await self.tg.delete(acc, mids)
            except TelegramError:
                self.store.queue_delete(acc, mids)

    async def _gc(self, cids: list[str]) -> None:
        """Delete Telegram messages of content no file uses any more. Content that is
        being downloaded right now is queued instead, so the download can finish."""
        doomed: list[dict[str, Any]] = []
        later: list[dict[str, Any]] = []
        with self.store.tx():
            for cid in set(cids):
                if cid and not self.store.cid_in_use(cid):
                    rows = self.store.delete_chunks(cid)
                    (later if self._readers.get(cid) else doomed).extend(rows)
        for c in later:
            self.store.queue_delete(c["account_id"], [c["message_id"]],
                                    not_before=time.time() + GC_GRACE)
        await self._discard(doomed)

    async def flush_deletes(self) -> None:
        for acc, mids in self.store.pending_deletes().items():
            try:
                await self.tg.delete(acc, mids)
                self.store.clear_deletes(acc, mids)
            except TelegramError:
                continue

    # -- download ----------------------------------------------------------------------------
    async def read(self, path: str, range_header: Optional[str] = None) -> tuple[Entry, Download]:
        parts = split(path)
        node = self._resolve(parts)
        if node is None:
            raise DriveError("not found", 404)
        if node["is_dir"]:
            raise DriveError("is a folder", 400)
        entry = self._entry(node, join(parts))
        size = node["size"]
        rng = parse_range(range_header, size) if size else None
        start, end = rng if rng else (0, size - 1)
        chunks = self.store.chunks(node["cid"]) if node["cid"] else []
        if size and sum(c["plain_size"] for c in chunks) != size:
            raise DriveError("some parts of this file are missing; link its accounts or rebuild", 500)
        linked = {a["id"] for a in self.store.accounts()}
        if any(c["account_id"] not in linked for c in chunks):
            raise DriveError("a part of this file is stored in an account that is no longer "
                             "linked; link it again or rebuild", 503)
        gen = self._track(node["cid"], self._stream(node["cid"], chunks, start, end)) if size else _empty()
        status = 206 if rng else 200
        content_range = f"bytes {start}-{end}/{size}" if rng else None
        return entry, Download(gen, (end - start + 1) if size else 0, node["mime"], status,
                               content_range)

    async def _track(self, cid: str, agen: AsyncIterator[bytes]) -> AsyncIterator[bytes]:
        self._readers[cid] = self._readers.get(cid, 0) + 1
        try:
            async for data in agen:
                yield data
        finally:
            await agen.aclose()  # type: ignore[attr-defined]
            left = self._readers.get(cid, 1) - 1
            if left > 0:
                self._readers[cid] = left
            else:
                self._readers.pop(cid, None)

    async def _stream(self, cid: str, chunks: list[dict[str, Any]], start: int,
                      end: int) -> AsyncIterator[bytes]:
        fkey = crypto.file_key(self._key(), cid)
        offset = 0
        for c in chunks:
            c_start, c_end = offset, offset + c["plain_size"] - 1
            offset += c["plain_size"]
            if c_end < start or c_start > end:
                continue
            lo, hi = max(start, c_start) - c_start, min(end, c_end) - c_start
            first_seg, s_off, s_len = crypto.plain_to_stored(lo, hi, c["plain_size"])
            seg = first_seg
            pos_plain = first_seg * crypto.SEGMENT  # plaintext offset of `seg` in the chunk
            buf = bytearray()
            agen = self.tg.download(c["account_id"], c["message_id"], s_off, s_len)
            try:
                async for data in agen:
                    buf += data
                    while True:
                        need = min(crypto.SEGMENT, c["plain_size"] - seg * crypto.SEGMENT) + crypto.TAG
                        if len(buf) < need:
                            break
                        block = bytes(buf[:need])
                        del buf[:need]
                        plain = next(crypto.decrypt_segments(fkey, cid, c["idx"], c["prefix"],
                                                             c["plain_size"], seg, block))
                        a = max(lo - pos_plain, 0)
                        b = min(hi - pos_plain + 1, len(plain))
                        if a < b:
                            yield plain[a:b]
                        seg += 1
                        pos_plain += crypto.SEGMENT
                        if pos_plain > hi:
                            break
                    if pos_plain > hi:
                        break
            except TelegramError as e:
                raise DriveError(f"download from Telegram failed: {e}", e.status) from e
            except crypto.DecryptError as e:
                raise DriveError(f"a stored part failed its integrity check: {e}", 500) from e
            finally:
                await agen.aclose()

    # -- changes -------------------------------------------------------------------------------
    async def delete(self, path: str) -> None:
        parts = split(path)
        if not parts:
            raise DriveError("cannot delete the root", 403)
        node = self._resolve(parts)
        if node is None:
            raise DriveError("not found", 404)
        nodes = self.store.subtree(node["id"])
        with self.store.tx():
            self.store.delete_nodes([n["id"] for n in nodes])
        await self._gc([n["cid"] for n in nodes if n["cid"]])
        self._changed()

    async def move(self, src: str, dst: str, overwrite: bool = False) -> Entry:
        sparts, dparts = split(src), split(dst)
        if not sparts or not dparts:
            raise DriveError("cannot move the root", 403)
        if dparts[:len(sparts)] == sparts and dparts != sparts:
            raise DriveError("cannot move a folder into itself", 409)
        if sparts[:len(dparts)] == dparts and dparts != sparts:
            raise DriveError("cannot replace a folder with something inside it", 409)
        node = self._resolve(sparts)
        if node is None:
            raise DriveError("not found", 404)
        if sparts == dparts:
            return await self.stat(dst)
        parent = self._parent(dparts)
        name = self._check_name(dparts[-1])
        existing = self.store.child(parent["id"], name)
        if existing:
            if not overwrite:
                raise DriveError("destination exists", 412)
            await self.delete(dst)
            node = self._resolve(sparts)
            if node is None:
                raise DriveError("not found", 404)
        self.store.update_node(node["id"], parent=parent["id"], name=name, modified=time.time())
        self._changed()
        return await self.stat(dst)

    async def copy(self, src: str, dst: str, overwrite: bool = False) -> Entry:
        sparts, dparts = split(src), split(dst)
        if not dparts or dparts[:len(sparts)] == sparts or sparts[:len(dparts)] == dparts:
            raise DriveError("invalid destination", 409)
        node = self._resolve(sparts)
        if node is None:
            raise DriveError("not found", 404)
        parent = self._parent(dparts)
        if self.store.child(parent["id"], dparts[-1]):
            if not overwrite:
                raise DriveError("destination exists", 412)
            await self.delete(dst)
            node = self._resolve(sparts)
            if node is None:
                raise DriveError("not found", 404)
        now = time.time()

        def clone(n: dict[str, Any], parent_id: str, name: str) -> None:
            new_id = secrets.token_hex(12)
            self.store.insert_node({"id": new_id, "parent": parent_id, "name": name,
                                    "is_dir": n["is_dir"], "cid": n["cid"], "size": n["size"],
                                    "mime": n["mime"], "created": now, "modified": now})
            if n["is_dir"]:
                for c in self.store.children(n["id"]):
                    clone(c, new_id, c["name"])

        with self.store.tx():
            clone(node, parent["id"], self._check_name(dparts[-1]))
        self._changed()
        return await self.stat(dst)

    # -- index snapshots and rebuild ----------------------------------------------------------
    def _export(self) -> bytes:
        tg_ids = {a["id"]: a["tg_user_id"] for a in self.store.accounts()}
        nodes = self.store.all_nodes()
        chunks = [{**c, "prefix": _b64(c["prefix"]), "tg": tg_ids.get(c["account_id"])}
                  for c in self.store.all_chunks()]
        data = json.dumps({"v": 1, "t": time.time(), "nodes": nodes, "chunks": chunks},
                          separators=(",", ":")).encode()
        return crypto.seal_blob(self._key(), "index", zlib.compress(data, 6))

    async def snapshot(self) -> Optional[str]:
        """Upload an encrypted copy of the index; keep the newest few."""
        async with self._snap_lock:
            accounts = self.active_accounts()
            if self.master is None or not accounts:
                return None
            self._dirty_since = None
            blob = self._export()
            acc = accounts[0]["id"]
            try:
                mid = await self.tg.upload(acc, io.BytesIO(blob), len(blob), "tgdrive-index.bin",
                                           TAG_INDEX + str(int(time.time())))
            except TelegramError:
                self._changed()
                raise
            history = json.loads(self.store.get("snapshots", "[]"))
            history.append([acc, mid])
            for old_acc, old_mid in history[:-KEEP_SNAPSHOTS]:
                try:
                    await self.tg.delete(old_acc, [old_mid])
                except TelegramError:
                    self.store.queue_delete(old_acc, [old_mid])
            self.store.set("snapshots", json.dumps(history[-KEEP_SNAPSHOTS:]))
            self.store.set("last_snapshot", str(time.time()))
            return f"{acc}:{mid}"

    async def check_key(self, master: bytes) -> Optional[bool]:
        """Does this key open what is already stored in the linked accounts?
        None when nothing encrypted was found to test it against."""
        for acc in self.active_accounts():
            gen = self.tg.iter_tagged(acc["id"], "tgdrive:")
            try:
                async for m in gen:
                    if m.text.startswith(TAG_CHUNK):
                        try:
                            crypto.open_blob(master, "caption", _unb64(m.text[len(TAG_CHUNK):]))
                            return True
                        except (crypto.DecryptError, ValueError):
                            return False
                    if m.text.startswith(TAG_INDEX) and m.size:
                        raw = await self._read_message(acc["id"], m.message_id, m.size)
                        try:
                            crypto.open_blob(master, "index", raw)
                            return True
                        except crypto.DecryptError:
                            return False
            except TelegramError as e:
                self.errors[acc["id"]] = str(e)
            finally:
                await gen.aclose()  # type: ignore[attr-defined]
        return None

    async def _read_message(self, account_id: int, message_id: int, size: int) -> bytes:
        out = bytearray()
        async for part in self.tg.download(account_id, message_id, 0, size):
            out += part
        return bytes(out)

    async def rebuild(self) -> dict[str, int]:
        """Restore the tree from the newest index snapshot and recover any files uploaded
        after it. Safe to run on a non-empty drive: restored items go to a new folder."""
        key = self._key()
        accounts = self.active_accounts()
        if not accounts:
            raise DriveError("link at least one Telegram account first", 409)
        by_tg = {a["tg_user_id"]: a["id"] for a in self.store.accounts()}
        newest: Optional[tuple[float, int, Any]] = None
        captions: list[tuple[int, Any]] = []
        for acc in accounts:
            try:
                async for m in self.tg.iter_tagged(acc["id"], "tgdrive:"):
                    if m.text.startswith(TAG_INDEX):
                        if newest is None or m.date > newest[0]:
                            newest = (m.date, acc["id"], m)
                    elif m.text.startswith(TAG_CHUNK):
                        captions.append((acc["id"], m))
            except TelegramError as e:
                self.errors[acc["id"]] = str(e)
        stats = {"files": 0, "folders": 0, "recovered": 0, "skipped": 0, "repaired": 0}
        linked = {a["id"] for a in self.store.accounts()}
        stale = {(c["cid"], c["idx"]) for c in self.store.all_chunks()
                 if c["account_id"] not in linked}
        empty = not self.store.children(ROOT)
        now = time.time()
        target = ROOT
        if not empty:
            target = secrets.token_hex(12)
            self.store.insert_node({"id": target, "parent": ROOT,
                                    "name": f"Restored {time.strftime('%Y-%m-%d %H.%M')}",
                                    "is_dir": 1, "cid": None, "size": 0,
                                    "mime": "inode/directory", "created": now, "modified": now})
        known = {c["cid"] for c in self.store.all_chunks()}
        if newest is not None:
            _, acc_id, msg = newest
            raw = await self._read_message(acc_id, msg.message_id, msg.size or 0)
            try:
                data = json.loads(zlib.decompress(crypto.open_blob(key, "index", raw)))
            except crypto.DecryptError as e:
                raise DriveError("the recovery key does not match this backup; enter the right "
                                 "one in Settings → Encryption and backup", 400) from e
            idmap = {ROOT: target}
            restored: set[str] = set()
            with self.store.tx():
                for c in data["chunks"]:
                    local = by_tg.get(c.get("tg"))
                    if local is None:
                        stats["skipped"] += 1
                        continue
                    if c["cid"] in known:
                        continue  # this content is already in the drive
                    self.store.insert_chunk({**c, "account_id": local, "prefix": _unb64(c["prefix"])})
                    restored.add(c["cid"])
                nodes = {n["id"]: n for n in data["nodes"] if n["id"] != ROOT}

                def place(nid: str) -> Optional[str]:
                    if nid in idmap:
                        return idmap[nid]
                    n = nodes.get(nid)
                    if n is None:
                        return None
                    parent = place(n["parent"]) if n["parent"] else target
                    if parent is None:
                        return None
                    new_id = n["id"] if empty else secrets.token_hex(12)
                    name = n["name"]
                    while self.store.child(parent, name):
                        name = f"{name} (restored)"
                    self.store.insert_node({**n, "id": new_id, "parent": parent, "name": name})
                    idmap[nid] = new_id
                    stats["folders" if n["is_dir"] else "files"] += 1
                    return new_id

                for nid in list(nodes):
                    place(nid)
            known |= restored
        # files uploaded after the last snapshot: rebuild them from their captions
        groups: dict[str, dict[int, tuple[int, Any, dict]]] = {}
        for acc_id, m in captions:
            try:
                meta = json.loads(crypto.open_blob(key, "caption", _unb64(m.text[len(TAG_CHUNK):])))
            except (crypto.DecryptError, ValueError):
                continue
            if (meta["c"], meta["i"]) in stale:
                # a part whose account was unlinked and linked again: point it at the new link
                old = [x for x in self.store.chunks(meta["c"]) if x["idx"] == meta["i"]][0]
                self.store.insert_chunk({**old, "account_id": acc_id, "message_id": m.message_id})
                stale.discard((meta["c"], meta["i"]))
                stats["repaired"] += 1
                continue
            if meta["c"] in known:
                continue
            groups.setdefault(meta["c"], {})[meta["i"]] = (acc_id, m, meta)
        if groups:
            folder = None
            for cid, parts in groups.items():
                meta = next(iter(parts.values()))[2]
                if len(parts) != meta["n"]:
                    stats["skipped"] += 1
                    continue
                if folder is None:
                    folder = self.store.child(target, "Recovered files")
                    if folder is None:
                        folder = {"id": secrets.token_hex(12), "parent": target,
                                  "name": "Recovered files", "is_dir": 1, "cid": None, "size": 0,
                                  "mime": "inode/directory", "created": now, "modified": now}
                        self.store.insert_node(folder)
                name = meta["nm"] or cid[:12]
                while self.store.child(folder["id"], name):
                    name = "copy of " + name
                with self.store.tx():
                    for i, (acc_id, m, mm) in parts.items():
                        self.store.insert_chunk({"cid": cid, "idx": i, "account_id": acc_id,
                                                 "message_id": m.message_id,
                                                 "plain_size": mm["ps"],
                                                 "stored_size": m.size or crypto.stored_size(mm["ps"]),
                                                 "prefix": _unb64(mm["p"])})
                    self.store.insert_node({"id": secrets.token_hex(12), "parent": folder["id"],
                                            "name": name, "is_dir": 0, "cid": cid,
                                            "size": meta["s"], "mime": meta["m"],
                                            "created": now, "modified": now})
                stats["recovered"] += 1
        self._changed()
        return stats

    # -- accounts --------------------------------------------------------------------------------
    async def evacuate(self, account_id: int) -> int:
        """Move every part stored in one account to the others (before unlinking it)."""
        others = [a for a in self.active_accounts() if a["id"] != account_id]
        if not others:
            raise DriveError("link another Telegram account first, to move the files to", 409)
        rows = [c for c in self.store.all_chunks() if c["account_id"] == account_id]
        usage = self.store.account_usage()
        moved = 0
        for c in rows:
            target = min(others, key=lambda a: usage.get(a["id"], (0, 0))[0])["id"]
            with tempfile.SpooledTemporaryFile(max_size=64 * 1024 * 1024) as buf:
                async for part in self.tg.download(account_id, c["message_id"], 0, c["stored_size"]):
                    buf.write(part)
                meta = {"c": c["cid"], "i": c["idx"], "n": len(self.store.chunks(c["cid"])),
                        "s": 0, "ps": c["plain_size"], "p": _b64(c["prefix"]), "m": "", "nm": "",
                        "pa": ""}
                node = self.store.node_by_cid(c["cid"])
                if node:
                    meta.update(s=node["size"], m=node["mime"], nm=node["name"][:150])
                mid = await self.tg.upload(target, buf, c["stored_size"],
                                           f"{c['cid'][:12]}.{c['idx']:05d}.bin", self._caption(meta))
            with self.store.tx():
                still = [x for x in self.store.chunks(c["cid"]) if x["idx"] == c["idx"]
                         and x["account_id"] == account_id and x["message_id"] == c["message_id"]]
                if still:
                    self.store.insert_chunk({**c, "account_id": target, "message_id": mid})
            if not still:  # the file was deleted while its part was being moved
                await self._discard([{"account_id": target, "message_id": mid}])
                continue
            u = usage.get(target, (0, 0))
            usage[target] = (u[0] + c["stored_size"], u[1] + 1)
            try:
                await self.tg.delete(account_id, [c["message_id"]])
            except TelegramError:
                self.store.queue_delete(account_id, [c["message_id"]])
            moved += 1
        self._changed()
        return moved


async def _empty() -> AsyncIterator[bytes]:
    if False:  # pragma: no cover
        yield b""
