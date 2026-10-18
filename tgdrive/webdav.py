"""WebDAV (RFC 4918, class 1 and 2) so the unified drive mounts as a network drive.

Works with Windows "Map network drive", macOS Finder "Connect to Server",
Linux file managers (davs://), rclone and mobile WebDAV apps. Locks are kept in
memory and enforced for WebDAV clients; custom ("dead") properties such as
Windows file times are stored in the local database.
"""
from __future__ import annotations

import base64
import email.utils
import html
import io
import re
import tempfile
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Optional
from urllib.parse import quote, unquote, unquote_to_bytes, urlparse
from xml.etree import ElementTree as ET

from starlette.requests import Request
from starlette.responses import Response, StreamingResponse

from .drive import Drive as Hub, DriveError as HubError, Entry, join, split

DAV = "DAV:"
ALLOW = ("OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, "
         "LOCK, UNLOCK")
SPOOL = 64 * 1024 * 1024
LIVE = {f"{{{DAV}}}{n}" for n in (
    "displayname", "getlastmodified", "resourcetype", "getcontentlength", "getcontenttype",
    "getetag", "supportedlock", "lockdiscovery", "quota-used-bytes", "quota-available-bytes",
    "creationdate")}
XML_HEAD = b'<?xml version="1.0" encoding="utf-8"?>\n'
SANDBOX = {"Content-Security-Policy": "sandbox; default-src 'none'"}
ET.register_namespace("D", DAV)


def _t(name: str) -> str:
    return f"{{{DAV}}}{name}"


def _http_date(rfc3339: Optional[str]) -> str:
    if not rfc3339:
        return email.utils.formatdate(usegmt=True)
    try:
        dt = datetime.fromisoformat(rfc3339.replace("Z", "+00:00"))
        return email.utils.format_datetime(dt, usegmt=True)
    except ValueError:
        return email.utils.formatdate(usegmt=True)


def _etag(e: Entry) -> str:
    return f'"{e.etag}"'


def _xml(root: ET.Element, status: int = 207, headers: Optional[dict] = None) -> Response:
    return Response(XML_HEAD + ET.tostring(root), status, headers=headers,
                    media_type='application/xml; charset="utf-8"')


# -- locks ---------------------------------------------------------------------------

@dataclass
class Lock:
    token: str
    path: str
    exclusive: bool
    infinite: bool
    owner: str  # serialized <D:owner> element, may be empty
    timeout: int
    expires: float

    def covers(self, path: str) -> bool:
        if path == self.path:
            return True
        prefix = self.path.rstrip("/") + "/"
        return self.infinite and path.startswith(prefix)


class LockManager:
    def __init__(self):
        self.locks: dict[str, Lock] = {}

    def _purge(self) -> None:
        now = time.time()
        for t in [t for t, l in self.locks.items() if l.expires < now]:
            del self.locks[t]

    def covering(self, path: str) -> list[Lock]:
        self._purge()
        return [l for l in self.locks.values() if l.covers(path)]

    def under(self, path: str) -> list[Lock]:
        prefix = path.rstrip("/") + "/"
        return [l for l in self.locks.values() if l.path == path or l.path.startswith(prefix)]

    def create(self, path: str, exclusive: bool, infinite: bool, owner: str, timeout: int) -> Lock:
        conflicts = self.covering(path) + (self.under(path) if infinite else [])
        if any(l.exclusive or exclusive for l in conflicts):
            raise HubError("resource is locked", 423)
        lock = Lock(f"opaquelocktoken:{uuid.uuid4()}", path, exclusive, infinite, owner,
                    timeout, time.time() + timeout)
        self.locks[lock.token] = lock
        return lock

    def drop_under(self, path: str) -> None:
        for l in self.under(path):
            self.locks.pop(l.token, None)


def _timeout(header: Optional[str]) -> int:
    for part in (header or "").split(","):
        part = part.strip()
        if part.lower().startswith("second-"):
            try:
                return max(1, min(int(part[7:]), 7 * 86400))
            except ValueError:
                pass
        if part.lower() == "infinite":
            return 7 * 86400
    return 3600


# -- If header (RFC 4918 section 10.4) -------------------------------------------------

_IF_TOKEN = re.compile(r'\s*(<[^>]*>|\(|\)|\[[^\]]*\]|Not\b)', re.I)


def parse_if(header: str) -> list[tuple[Optional[str], list[list[tuple[bool, str, str]]]]]:
    """Returns [(resource_tag_or_None, [list_of_conditions, ...]), ...] where each condition
    is (negated, "token"|"etag", value)."""
    groups: list[tuple[Optional[str], list]] = []
    tag: Optional[str] = None
    pos = 0
    current: Optional[list] = None
    negate = False
    while pos < len(header):
        m = _IF_TOKEN.match(header, pos)
        if not m:
            if header[pos:].strip():
                raise HubError("malformed If header", 400)
            break
        tok = m.group(1)
        pos = m.end()
        if tok == "(":
            current = []
            if not groups or groups[-1][0] != tag:
                groups.append((tag, []))
        elif tok == ")":
            if current is None:
                raise HubError("malformed If header", 400)
            groups[-1][1].append(current)
            current, negate = None, False
        elif tok.lower() == "not":
            negate = True
        elif tok.startswith("<"):
            if current is None:  # resource tag
                tag = tok[1:-1]
            else:
                current.append((negate, "token", tok[1:-1]))
                negate = False
        elif tok.startswith("["):
            if current is None:
                raise HubError("malformed If header", 400)
            current.append((negate, "etag", tok[1:-1]))
            negate = False
    return groups


def basic_credentials(request: Request) -> Optional[tuple[str, str]]:
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("basic "):
        return None
    try:
        user, _, pw = base64.b64decode(auth[6:]).decode("utf-8").partition(":")
        return user, pw
    except Exception:
        return None


class WebDAV:
    def __init__(self, hub: Hub, prefix: str, authenticate: Callable[[Request], bool],
                 props=None):
        self.hub = hub
        self.prefix = prefix.rstrip("/")
        self.authenticate = authenticate
        self.props = props  # Store, for dead properties (optional)
        self.locks = LockManager()

    # -- paths ---------------------------------------------------------------------
    def _path(self, request: Request) -> str:
        # Use the raw, still-encoded request path and decode it exactly once, so names
        # containing %, # or ? are not truncated or decoded twice.
        raw = request.scope.get("raw_path") or request.url.path.encode()
        path = unquote_to_bytes(raw.split(b"?", 1)[0]).decode("utf-8", "replace")
        return self._decoded_to_path(path)

    def _url_to_path(self, url: str) -> str:
        return self._decoded_to_path(unquote(urlparse(url).path))

    def _decoded_to_path(self, path: str) -> str:
        if path != self.prefix and not path.startswith(self.prefix + "/"):
            raise HubError("outside this server", 502)
        return join(split(path[len(self.prefix):]))

    def _href(self, path: str, is_dir: bool) -> str:
        href = self.prefix + quote(path)
        return href + "/" if is_dir and not href.endswith("/") else href

    def _dest(self, request: Request) -> str:
        dest = request.headers.get("destination")
        if not dest:
            raise HubError("missing Destination header", 400)
        return self._url_to_path(dest)

    # -- preconditions -----------------------------------------------------------------
    async def _etag_of(self, path: str) -> Optional[str]:
        try:
            e = await self.hub.stat(path)
        except HubError:
            return None
        return None if e.is_dir else _etag(e)

    async def _check(self, request: Request, *paths: str, deep: tuple[str, ...] = ()) -> None:
        """Evaluate the If header (412 when false) and require lock tokens for every
        locked resource the request changes (423 when missing)."""
        header = request.headers.get("if")
        submitted: set[str] = set()
        if header:
            groups = parse_if(header)
            ok = False
            for tag, lists in groups:
                target = self._url_to_path(tag) if tag else self._path(request)
                for conds in lists:
                    if await self._list_true(target, conds):
                        ok = True
                    submitted |= {v for neg, kind, v in conds if kind == "token" and not neg}
            if not ok:
                raise HubError("precondition failed", 412)
        for path in paths:
            for lock in self.locks.covering(path):
                if lock.token not in submitted:
                    raise HubError("resource is locked", 423)
        for path in deep:
            for lock in self.locks.under(path):
                if lock.token not in submitted:
                    raise HubError("a resource inside is locked", 423)

    async def _list_true(self, path: str, conds: list[tuple[bool, str, str]]) -> bool:
        tokens = {l.token for l in self.locks.covering(path)}
        etag = None
        for neg, kind, value in conds:
            if kind == "token":
                res = value in tokens
            else:
                if etag is None:
                    etag = await self._etag_of(path) or ""
                res = value == etag
            if res == neg:
                return False
        return True

    # -- dispatch ----------------------------------------------------------------------
    async def __call__(self, request: Request) -> Response:
        if request.method != "OPTIONS" and not self.authenticate(request):
            return Response("Authentication required", 401, headers={
                "WWW-Authenticate": 'Basic realm="Telegram Drive", charset="UTF-8"'})
        handler = getattr(self, "do_" + request.method.lower(), None)
        if handler is None:
            return Response(status_code=405, headers={"Allow": ALLOW})
        try:
            return await handler(request)
        except HubError as e:
            return Response(str(e), e.status)

    async def do_options(self, request: Request) -> Response:
        return Response(headers={"DAV": "1, 2", "Allow": ALLOW, "MS-Author-Via": "DAV"})

    # -- properties ----------------------------------------------------------------------
    def _lockdiscovery(self, parent: ET.Element, path: str) -> None:
        ld = ET.SubElement(parent, _t("lockdiscovery"))
        for lock in self.locks.covering(path):
            self._activelock(ld, lock)

    def _activelock(self, parent: ET.Element, lock: Lock) -> None:
        al = ET.SubElement(parent, _t("activelock"))
        ET.SubElement(ET.SubElement(al, _t("locktype")), _t("write"))
        ET.SubElement(ET.SubElement(al, _t("lockscope")), _t("exclusive" if lock.exclusive else "shared"))
        ET.SubElement(al, _t("depth")).text = "infinity" if lock.infinite else "0"
        if lock.owner:
            al.append(ET.fromstring(lock.owner))
        ET.SubElement(al, _t("timeout")).text = f"Second-{max(0, int(lock.expires - time.time()))}"
        ET.SubElement(ET.SubElement(al, _t("locktoken")), _t("href")).text = lock.token
        ET.SubElement(ET.SubElement(al, _t("lockroot")), _t("href")).text = \
            self._href(lock.path, False)

    def _live(self, e: Entry, name: str, quota: Optional[tuple[int, int]]) -> Optional[ET.Element]:
        el = ET.Element(name)
        local = name.split("}")[1]
        if local == "displayname":
            el.text = e.name or "Telegram Drive"
        elif local == "getlastmodified":
            el.text = _http_date(e.modified)
        elif local == "creationdate":
            el.text = (e.modified or "1970-01-01T00:00:00Z")
        elif local == "resourcetype":
            if e.is_dir:
                ET.SubElement(el, _t("collection"))
        elif local == "getcontentlength" and not e.is_dir and e.size is not None:
            el.text = str(e.size)
        elif local == "getcontenttype" and not e.is_dir:
            el.text = e.mime
        elif local == "getetag" and not e.is_dir:
            el.text = _etag(e)
        elif local == "supportedlock":
            for scope in ("exclusive", "shared"):
                le = ET.SubElement(el, _t("lockentry"))
                ET.SubElement(ET.SubElement(le, _t("lockscope")), _t(scope))
                ET.SubElement(ET.SubElement(le, _t("locktype")), _t("write"))
        elif local == "lockdiscovery":
            for lock in self.locks.covering(e.path):
                self._activelock(el, lock)
        elif local == "quota-used-bytes" and quota:
            el.text = str(quota[0])
        elif local == "quota-available-bytes" and quota:
            el.text = str(quota[1])
        else:
            return None
        return el

    def _dead(self, path: str) -> dict[str, str]:
        return self.props.props(path) if self.props else {}

    async def do_propfind(self, request: Request) -> Response:
        path = self._path(request)
        depth = request.headers.get("depth", "infinity")
        body = await request.body()
        mode, wanted = "allprop", []
        if body.strip():
            try:
                root = ET.fromstring(body)
            except ET.ParseError:
                return Response("malformed XML", 400)
            if root.tag != _t("propfind"):
                return Response("expected propfind", 400)
            if root.find(_t("propname")) is not None:
                mode = "propname"
            elif root.find(_t("prop")) is not None:
                mode = "prop"
                wanted = [c.tag for c in root.find(_t("prop"))]
        entry = await self.hub.stat(path)
        entries = [entry]
        if entry.is_dir and depth != "0":
            entries += await self.hub.ls(path)
        quota = None
        if path == "/":
            qs = [q for _, q in await self.hub.quotas() if q]
            if qs:
                quota = (sum(q.used for q in qs), sum(q.free for q in qs))
        ms = ET.Element(_t("multistatus"))
        for e in entries:
            resp = ET.SubElement(ms, _t("response"))
            ET.SubElement(resp, _t("href")).text = self._href(e.path, e.is_dir)
            dead = self._dead(e.path)
            found, missing = [], []
            if mode == "prop":
                for name in wanted:
                    if name in LIVE:
                        el = self._live(e, name, quota if e is entry else None)
                        (found if el is not None else missing).append(el if el is not None else ET.Element(name))
                    elif name in dead:
                        found.append(ET.fromstring(dead[name]))
                    else:
                        missing.append(ET.Element(name))
            else:
                names = ["displayname", "getlastmodified", "resourcetype", "supportedlock",
                         "lockdiscovery", "creationdate"]
                if not e.is_dir:
                    names += ["getcontentlength", "getcontenttype", "getetag"]
                if quota and e is entry:
                    names += ["quota-used-bytes", "quota-available-bytes"]
                for n in names:
                    el = self._live(e, _t(n), quota if e is entry else None)
                    if el is not None:
                        found.append(ET.Element(el.tag) if mode == "propname" else el)
                for name, value in dead.items():
                    found.append(ET.Element(name) if mode == "propname" else ET.fromstring(value))
            for elements, status in ((found, "200 OK"), (missing, "404 Not Found")):
                if not elements:
                    continue
                ps = ET.SubElement(resp, _t("propstat"))
                prop = ET.SubElement(ps, _t("prop"))
                prop.extend(elements)
                ET.SubElement(ps, _t("status")).text = f"HTTP/1.1 {status}"
        return _xml(ms)

    async def do_proppatch(self, request: Request) -> Response:
        path = self._path(request)
        await self.hub.stat(path)
        await self._check(request, path)
        try:
            root = ET.fromstring(await request.body())
        except ET.ParseError:
            return Response("malformed XML", 400)
        if root.tag != _t("propertyupdate"):
            return Response("expected propertyupdate", 400)
        updates: dict[str, Optional[str]] = {}
        order: list[str] = []
        protected: list[str] = []
        for action in root:
            if action.tag not in (_t("set"), _t("remove")):
                continue
            prop = action.find(_t("prop"))
            for el in (list(prop) if prop is not None else []):
                order.append(el.tag)
                if el.tag in LIVE:
                    protected.append(el.tag)
                elif action.tag == _t("set"):
                    updates[el.tag] = ET.tostring(el, encoding="unicode")
                else:
                    updates[el.tag] = None
        ms = ET.Element(_t("multistatus"))
        resp = ET.SubElement(ms, _t("response"))
        ET.SubElement(resp, _t("href")).text = self.prefix + quote(path)
        if protected or self.props is None:
            groups = (([n for n in order if n in protected or self.props is None], "403 Forbidden"),
                      ([n for n in order if n not in protected and self.props is not None],
                       "424 Failed Dependency"))
        else:
            self.props.set_props(path, updates)
            groups = ((order, "200 OK"),)
        for names, status in groups:
            if not names:
                continue
            ps = ET.SubElement(resp, _t("propstat"))
            prop = ET.SubElement(ps, _t("prop"))
            for n in dict.fromkeys(names):
                ET.SubElement(prop, n)
            ET.SubElement(ps, _t("status")).text = f"HTTP/1.1 {status}"
        return _xml(ms)

    # -- content ---------------------------------------------------------------------------
    async def _get(self, request: Request, head: bool) -> Response:
        path = self._path(request)
        e = await self.hub.stat(path)
        if e.is_dir:
            if head:
                return Response(media_type="text/html")
            items = "".join(
                f'<li><a href="{html.escape(self._href(c.path, c.is_dir))}">'
                f'{html.escape(c.name)}{"/" if c.is_dir else ""}</a></li>'
                for c in await self.hub.ls(path))
            title = html.escape(e.name or "Telegram Drive")
            return Response(f"<!doctype html><title>{title}</title><ul>{items}</ul>",
                            media_type="text/html", headers=SANDBOX)
        # Files are always downloads in a sandbox, never active content on this origin.
        headers = {"ETag": _etag(e), "Last-Modified": _http_date(e.modified),
                   "Accept-Ranges": "bytes", **SANDBOX,
                   "Content-Disposition": f"attachment; filename*=UTF-8''{quote(e.name)}"}
        if head:
            if e.size is not None:
                headers["Content-Length"] = str(e.size)
            return Response(headers=headers, media_type=e.mime)
        _, dl = await self.hub.read(path, request.headers.get("range"))
        if dl.size is not None:
            headers["Content-Length"] = str(dl.size)
        if dl.content_range:
            headers["Content-Range"] = dl.content_range

        async def body():
            try:
                async for chunk in dl.chunks:
                    yield chunk
            finally:
                await dl.aclose()
        return StreamingResponse(body(), dl.status, headers=headers, media_type=dl.mime)

    async def do_get(self, request: Request) -> Response:
        return await self._get(request, head=False)

    async def do_head(self, request: Request) -> Response:
        return await self._get(request, head=True)

    async def do_put(self, request: Request) -> Response:
        path = self._path(request)
        await self._check(request, path)
        try:
            existing = await self.hub.stat(path)
        except HubError as e:
            if e.status != 404:
                raise
            existing = None
        if existing and existing.is_dir:
            return Response("is a collection", 405)
        with tempfile.SpooledTemporaryFile(max_size=SPOOL) as buf:
            async for chunk in request.stream():
                buf.write(chunk)
            size = buf.tell()
            buf.seek(0)
            try:
                await self.hub.write(path, buf, size, request.headers.get("content-type"))
            except HubError as e:
                if e.status == 404:
                    return Response("parent folder does not exist", 409)
                raise
        return Response(status_code=204 if existing else 201)

    async def do_mkcol(self, request: Request) -> Response:
        if await request.body():
            return Response(status_code=415)
        path = self._path(request)
        await self._check(request, path)
        try:
            await self.hub.mkdir(path)
        except HubError as e:
            if e.status == 404:
                return Response(status_code=409)  # parent missing
            raise
        return Response(status_code=201)

    async def do_delete(self, request: Request) -> Response:
        path = self._path(request)
        if request.url.fragment:
            return Response("fragments are not allowed", 400)
        await self.hub.stat(path)
        await self._check(request, path, deep=(path,))
        await self.hub.delete(path)
        self.locks.drop_under(path)
        if self.props:
            self.props.delete_props(path)
        return Response(status_code=204)

    async def _move_copy(self, request: Request, copy: bool) -> Response:
        src, dst = self._path(request), self._dest(request)
        if src == dst:
            return Response("source and destination are the same", 403)
        overwrite = request.headers.get("overwrite", "T").upper() != "F"
        await self.hub.stat(src)
        if copy:
            await self._check(request, dst, deep=(dst,))
        else:
            await self._check(request, src, dst, deep=(src, dst))
        existed = await self.hub.exists(dst)
        if existed and not overwrite:
            return Response("destination exists", 412)
        try:
            if copy:
                await self.hub.copy(src, dst, overwrite)
            else:
                await self.hub.move(src, dst, overwrite)
        except HubError as e:
            if e.status == 404 and await self.hub.exists(src):
                return Response(status_code=409)  # destination parent missing
            raise
        if not copy:
            self.locks.drop_under(src)
        if self.props:
            self.props.copy_props(src, dst, move=not copy)
        return Response(status_code=204 if existed else 201)

    async def do_move(self, request: Request) -> Response:
        return await self._move_copy(request, copy=False)

    async def do_copy(self, request: Request) -> Response:
        return await self._move_copy(request, copy=True)

    # -- locking -----------------------------------------------------------------------------
    async def do_lock(self, request: Request) -> Response:
        path = self._path(request)
        body = await request.body()
        timeout = _timeout(request.headers.get("timeout"))
        if not body.strip():  # refresh an existing lock
            header = request.headers.get("if", "")
            tokens = {v for _, lists in parse_if(header) for conds in lists
                      for neg, kind, v in conds if kind == "token" and not neg}
            lock = next((l for l in self.locks.covering(path) if l.token in tokens), None)
            if lock is None:
                return Response("no matching lock to refresh", 412)
            lock.timeout, lock.expires = timeout, time.time() + timeout
            prop = ET.Element(_t("prop"))
            self._activelock(ET.SubElement(prop, _t("lockdiscovery")), lock)
            return _xml(prop, 200)
        try:
            info = ET.fromstring(body)
        except ET.ParseError:
            return Response("malformed XML", 400)
        exclusive = info.find(f"{_t('lockscope')}/{_t('shared')}") is None
        owner_el = info.find(_t("owner"))
        owner = ET.tostring(owner_el, encoding="unicode") if owner_el is not None else ""
        infinite = request.headers.get("depth", "infinity").lower() != "0"
        exists = await self.hub.exists(path)
        await self._check(request)  # If header only; conflicts are decided by the lock manager
        lock = self.locks.create(path, exclusive, infinite, owner, timeout)
        if not exists:  # LOCK on an unmapped URL creates an empty file
            try:
                await self.hub.write(path, io.BytesIO(b""), 0)
            except HubError as e:
                self.locks.locks.pop(lock.token, None)
                return Response(str(e), 409 if e.status == 404 else e.status)
        prop = ET.Element(_t("prop"))
        self._activelock(ET.SubElement(prop, _t("lockdiscovery")), lock)
        return _xml(prop, 200 if exists else 201, headers={"Lock-Token": f"<{lock.token}>"})

    async def do_unlock(self, request: Request) -> Response:
        path = self._path(request)
        token = request.headers.get("lock-token", "").strip().strip("<>")
        lock = self.locks.locks.get(token)
        if lock is None or not lock.covers(path):
            return Response("lock token does not match", 409)
        del self.locks.locks[token]
        return Response(status_code=204)
