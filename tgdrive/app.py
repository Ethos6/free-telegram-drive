"""HTTP application: web UI, JSON API, Telegram login, share links and WebDAV."""
from __future__ import annotations

import asyncio
import base64
import logging
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Optional
from urllib.parse import quote

import segno
from fastapi import Body, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

from . import __version__, crypto
from .config import Settings
from .drive import Drive, DriveError, join, split
from .security import (Throttle, Vault, hash_password, new_totp_secret, token_hash,
                       totp_uri, verify_password, verify_totp)
from .store import Store
from .telegram import TelegramAPI, TelegramError, TelethonAPI
from .webdav import WebDAV, basic_credentials

log = logging.getLogger("tgdrive")
STATIC = Path(__file__).parent / "static"
COOKIE = "tgd_session"
HEADER = "x-tgdrive"
SAFE_INLINE = ("image/png", "image/jpeg", "image/gif", "image/webp", "image/avif",
               "application/pdf", "text/plain", "audio/", "video/")


def mask_phone(phone: str) -> str:
    digits = phone.lstrip("+")
    return "+" + digits[:2] + "•" * max(0, len(digits) - 5) + digits[-3:] if len(digits) > 5 else phone


def create_app(settings: Settings, store: Optional[Store] = None,
               telegram: Optional[TelegramAPI] = None) -> FastAPI:
    store = store or Store(settings.data_dir / "tgdrive.db")
    vault = Vault(settings.secret_key)
    tg: Optional[TelegramAPI] = telegram
    if tg is None and settings.telegram_configured:
        tg = TelethonAPI(settings.telegram_api_id, settings.telegram_api_hash)
    drive = Drive(store, tg, chunk_size=settings.chunk_mb * 1024 * 1024,  # type: ignore[arg-type]
                  parallel=settings.parallel)
    throttle = Throttle()
    state: dict[str, Any] = {"setup_token": None}

    def need_tg() -> TelegramAPI:
        if tg is None:
            raise HTTPException(400, "Set TELEGRAM_API_ID and TELEGRAM_API_HASH first (see README)")
        return tg

    def unlock_vault() -> None:
        sealed = store.get("master_sealed")
        if sealed:
            drive.unlock(base64.b64decode(vault.open(sealed)))

    async def attach_accounts() -> None:
        if tg is None:
            return
        for acc in store.accounts(include_disabled=False):
            try:
                await tg.attach(acc["id"], vault.open(acc["session"]))
            except ValueError as e:
                drive.errors[acc["id"]] = str(e)

    async def check_accounts() -> None:
        if tg is None:
            return
        for acc in store.accounts(include_disabled=False):
            try:
                await tg.whoami(acc["id"])
                drive.errors.pop(acc["id"], None)
            except TelegramError as e:
                drive.errors[acc["id"]] = str(e)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        store.purge_expired_sessions()
        if not store.get("password_hash"):
            state["setup_token"] = secrets.token_urlsafe(12)
            log.warning("First run: open %s and use setup code: %s", settings.base_url,
                        state["setup_token"])
            print(f"\n  Telegram Drive setup code: {state['setup_token']}\n", flush=True)
        unlock_vault()
        await attach_accounts()
        checker = asyncio.create_task(check_accounts())
        drive.start_background()
        yield
        checker.cancel()
        await drive.stop_background()
        if drive._dirty_since:
            try:
                await drive.snapshot()
            except Exception as e:
                log.warning("final index backup failed: %s", e)
        if tg is not None:
            await tg.close()

    app = FastAPI(title="Telegram Drive", version=__version__, lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)
    app.state.drive, app.state.store, app.state.settings, app.state.setup = drive, store, settings, state

    # -- helpers --------------------------------------------------------------------------
    def client_ip(request: Request) -> str:
        if settings.trust_proxy:
            fwd = request.headers.get("x-forwarded-for")
            if fwd:
                return fwd.split(",")[-1].strip()
        return request.client.host if request.client else "?"

    def logged_in(request: Request) -> bool:
        sid = request.cookies.get(COOKIE)
        return bool(sid) and store.session_valid(token_hash(sid))

    def require_login(request: Request) -> None:
        if not logged_in(request):
            raise HTTPException(401, "login required")

    def start_session(response: Response, request: Request) -> None:
        sid = secrets.token_urlsafe(32)
        store.create_session(token_hash(sid), settings.session_days,
                             request.headers.get("user-agent", ""))
        response.set_cookie(COOKIE, sid, max_age=settings.session_days * 86400, httponly=True,
                            samesite="lax", secure=settings.secure_cookies, path="/")

    def guard_attempts(request: Request, scope: str) -> str:
        key = f"{scope}:{client_ip(request)}"
        if throttle.blocked(key):
            raise HTTPException(429, "too many attempts; wait 15 minutes")
        return key

    async def check_password(request: Request, password: str) -> None:
        key = guard_attempts(request, "pw")
        if not await asyncio.to_thread(verify_password, password, store.get("password_hash") or ""):
            throttle.fail(key)
            raise HTTPException(403, "password is wrong")

    def dav_auth(request: Request) -> bool:
        creds = basic_credentials(request)  # app passwords only, never the browser session
        if not creds:
            return False
        key = "dav:" + client_ip(request)
        if throttle.blocked(key):
            return False
        if store.app_password_by_hash(token_hash(creds[1])) is not None:
            return True
        throttle.fail(key)
        return False

    def stream_response(entry, dl, inline: bool, extra_csp: str = "") -> StreamingResponse:
        safe = inline and any(entry.mime.startswith(t) for t in SAFE_INLINE)
        pdf = safe and entry.mime == "application/pdf"
        csp = ("default-src 'none'; frame-ancestors 'self'" if pdf else
               "sandbox; default-src 'none'; img-src 'self'; media-src 'self'; "
               "style-src 'unsafe-inline'; frame-ancestors 'self'")
        headers = {"Content-Disposition": f"{'inline' if safe else 'attachment'}; "
                                          f"filename*=UTF-8''{quote(entry.name)}",
                   "Accept-Ranges": "bytes", "Cache-Control": "private, no-store",
                   "Content-Security-Policy": csp, "X-Frame-Options": "SAMEORIGIN",
                   "Content-Length": str(dl.size)}
        if dl.content_range:
            headers["Content-Range"] = dl.content_range
        mime = entry.mime if safe else "application/octet-stream"
        if mime.startswith("text/"):
            mime = "text/plain; charset=utf-8"

        async def body():
            try:
                async for chunk in dl.chunks:
                    yield chunk
            finally:
                await dl.aclose()
        return StreamingResponse(body(), dl.status, headers=headers, media_type=mime)

    # -- middleware ---------------------------------------------------------------------------
    @app.middleware("http")
    async def guard(request: Request, call_next):
        if (request.url.path.startswith("/api/") and request.method not in ("GET", "HEAD", "OPTIONS")
                and request.headers.get(HEADER) != "1"):
            return JSONResponse({"detail": "missing X-TgDrive header"}, 403)
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data: blob:; media-src 'self' blob:; "
            "style-src 'self'; script-src 'self'; frame-src 'self'; object-src 'none'; "
            "frame-ancestors 'self'; base-uri 'none'; form-action 'self'")
        return response

    @app.exception_handler(DriveError)
    async def drive_error(request: Request, exc: DriveError):
        return JSONResponse({"detail": str(exc)}, exc.status)

    @app.exception_handler(TelegramError)
    async def tg_error(request: Request, exc: TelegramError):
        return JSONResponse({"detail": str(exc)}, exc.status)

    # -- pages ------------------------------------------------------------------------------------
    @app.get("/", include_in_schema=False)
    async def index():
        return FileResponse(STATIC / "index.html", headers={"Cache-Control": "no-cache"})

    @app.get("/sw.js", include_in_schema=False)
    async def service_worker():
        return FileResponse(STATIC / "sw.js", media_type="text/javascript",
                            headers={"Cache-Control": "no-cache"})

    @app.get("/manifest.webmanifest", include_in_schema=False)
    async def manifest():
        return FileResponse(STATIC / "manifest.webmanifest", media_type="application/manifest+json")

    app.mount("/static", StaticFiles(directory=STATIC), name="static")

    @app.get("/healthz", include_in_schema=False)
    async def healthz():
        return {"ok": True, "version": __version__}

    # -- sign-in --------------------------------------------------------------------------------
    @app.get("/api/status")
    async def status(request: Request):
        return {"version": __version__, "setup_needed": not store.get("password_hash"),
                "logged_in": logged_in(request), "totp_enabled": bool(store.get("totp_secret")),
                "vault_ready": drive.master is not None,
                "telegram_configured": tg is not None, "demo": settings.demo,
                "accounts": len(store.accounts(include_disabled=False)),
                "dav_url": settings.base_url + "/dav/"}

    @app.post("/api/setup")
    async def setup(request: Request, body: dict = Body(...)):
        if store.get("password_hash"):
            raise HTTPException(409, "already set up")
        key = guard_attempts(request, "setup")
        token = state["setup_token"]
        if not token or not secrets.compare_digest(str(body.get("setup_code", "")), token):
            throttle.fail(key)
            raise HTTPException(403, "wrong setup code (it is printed in the server log)")
        password = str(body.get("password", ""))
        if len(password) < 10:
            raise HTTPException(400, "use at least 10 characters")
        store.set("password_hash", hash_password(password))
        state["setup_token"] = None
        resp = JSONResponse({"ok": True})
        start_session(resp, request)
        return resp

    @app.post("/api/login")
    async def login(request: Request, body: dict = Body(...)):
        key = guard_attempts(request, "login")
        stored = store.get("password_hash")
        ok = bool(stored) and await asyncio.to_thread(verify_password, str(body.get("password", "")), stored)
        secret = store.get("totp_secret")
        if ok and secret and not verify_totp(secret, str(body.get("code", ""))):
            throttle.fail(key)
            raise HTTPException(401, "wrong or missing 2FA code" if body.get("code") else "2FA code required")
        if not ok:
            throttle.fail(key)
            raise HTTPException(401, "wrong password")
        throttle.reset(key)
        resp = JSONResponse({"ok": True})
        start_session(resp, request)
        return resp

    @app.post("/api/logout")
    async def logout(request: Request):
        sid = request.cookies.get(COOKIE)
        if sid:
            store.delete_session(token_hash(sid))
        resp = JSONResponse({"ok": True})
        resp.delete_cookie(COOKIE, path="/")
        return resp

    @app.post("/api/password")
    async def change_password(request: Request, body: dict = Body(...)):
        require_login(request)
        await check_password(request, str(body.get("current", "")))
        new = str(body.get("new", ""))
        if len(new) < 10:
            raise HTTPException(400, "use at least 10 characters")
        store.set("password_hash", hash_password(new))
        store.delete_all_sessions()
        resp = JSONResponse({"ok": True})
        start_session(resp, request)
        return resp

    @app.post("/api/totp/setup")
    async def totp_setup(request: Request):
        require_login(request)
        secret = new_totp_secret()
        uri = totp_uri(secret, "tgdrive")
        return {"secret": secret, "uri": uri,
                "qr_svg": segno.make(uri, error="m").svg_inline(scale=5, dark="#111", light="#fff")}

    @app.post("/api/totp/enable")
    async def totp_enable(request: Request, body: dict = Body(...)):
        require_login(request)
        secret, code = str(body.get("secret", "")), str(body.get("code", ""))
        if not secret or not verify_totp(secret, code):
            raise HTTPException(400, "code does not match; check your phone's clock")
        store.set("totp_secret", secret)
        return {"ok": True}

    @app.post("/api/totp/disable")
    async def totp_disable(request: Request, body: dict = Body(...)):
        require_login(request)
        await check_password(request, str(body.get("password", "")))
        store.set("totp_secret", None)
        return {"ok": True}

    @app.get("/api/app-passwords")
    async def list_app_passwords(request: Request):
        require_login(request)
        return store.app_passwords()

    @app.post("/api/app-passwords")
    async def create_app_password(request: Request, body: dict = Body(...)):
        require_login(request)
        name = str(body.get("name", "")).strip()[:60] or "WebDAV"
        raw = "-".join(secrets.token_hex(4) for _ in range(4))
        return {"id": store.add_app_password(name, token_hash(raw)), "name": name, "password": raw}

    @app.delete("/api/app-passwords/{pid}")
    async def delete_app_password(pid: int, request: Request):
        require_login(request)
        if not store.delete_app_password(pid):
            raise HTTPException(404, "not found")
        return {"ok": True}

    # -- vault (encryption key) ------------------------------------------------------------------
    def save_master(master: bytes) -> None:
        store.set("master_sealed", vault.seal(base64.b64encode(master).decode()))
        drive.unlock(master)

    @app.post("/api/vault/create")
    async def vault_create(request: Request):
        require_login(request)
        if drive.master is not None:
            raise HTTPException(409, "the vault already exists")
        master = crypto.new_master_key()
        save_master(master)
        return {"recovery_key": crypto.format_recovery_key(master)}

    @app.post("/api/vault/restore")
    async def vault_restore(request: Request, body: dict = Body(...)):
        require_login(request)
        if drive.master is not None:
            # replacing the key is only safe while nothing is encrypted with the current one
            if store.all_chunks():
                raise HTTPException(409, "the vault already holds files; its key cannot be replaced")
            await check_password(request, str(body.get("password", "")))
        key = guard_attempts(request, "restore")
        try:
            master = crypto.parse_recovery_key(str(body.get("recovery_key", "")))
        except ValueError as e:
            throttle.fail(key)
            raise HTTPException(400, str(e)) from e
        if await drive.check_key(master) is False:
            throttle.fail(key)
            raise HTTPException(400, "this recovery key does not match the files in your linked "
                                     "Telegram accounts")
        save_master(master)
        return {"ok": True}

    @app.post("/api/vault/recovery-key")
    async def vault_reveal(request: Request, body: dict = Body(...)):
        require_login(request)
        await check_password(request, str(body.get("password", "")))
        if drive.master is None:
            raise HTTPException(409, "the vault is not set up yet")
        return {"recovery_key": crypto.format_recovery_key(drive.master)}

    @app.post("/api/rebuild")
    async def rebuild(request: Request):
        require_login(request)
        return await drive.rebuild()

    @app.post("/api/backup")
    async def backup_now(request: Request):
        require_login(request)
        ref = await drive.snapshot()
        if ref is None:
            raise HTTPException(409, "link a Telegram account and set up the vault first")
        return {"ok": True}

    # -- Telegram accounts -----------------------------------------------------------------------
    async def finish_login(res) -> dict:
        label = (res.user.name.split(" ")[0] or "Telegram")[:20]
        aid = store.upsert_account(res.user.id, res.user.phone, res.user.name, label,
                                   vault.seal(res.session))
        await need_tg().attach(aid, res.session)
        drive.errors.pop(aid, None)
        return {"status": "ok", "account": {"id": aid, "name": res.user.name,
                                            "phone": mask_phone(res.user.phone)}}

    @app.post("/api/telegram/start")
    async def tg_start(request: Request, body: dict = Body(...)):
        require_login(request)
        key = guard_attempts(request, "tg")
        try:
            res = await need_tg().start_login(str(body.get("phone", "")))
        except TelegramError:
            throttle.fail(key)
            raise
        return {"status": res.status, "login_id": res.login_id}

    @app.post("/api/telegram/code")
    async def tg_code(request: Request, body: dict = Body(...)):
        require_login(request)
        key = guard_attempts(request, "tg")
        try:
            res = await need_tg().submit_code(str(body.get("login_id", "")), str(body.get("code", "")))
        except TelegramError:
            throttle.fail(key)
            raise
        if res.status == "password_needed":
            return {"status": "password_needed", "hint": res.hint}
        return await finish_login(res)

    @app.post("/api/telegram/password")
    async def tg_password(request: Request, body: dict = Body(...)):
        require_login(request)
        key = guard_attempts(request, "tg")
        try:
            res = await need_tg().submit_password(str(body.get("login_id", "")),
                                                  str(body.get("password", "")))
        except TelegramError:
            throttle.fail(key)
            raise
        return await finish_login(res)

    @app.get("/api/accounts")
    async def accounts(request: Request):
        require_login(request)
        usage = store.account_usage()
        rows = [{"id": a["id"], "label": a["label"], "name": a["name"],
                 "phone": mask_phone(a["phone"]), "stored": usage.get(a["id"], (0, 0))[0],
                 "parts": usage.get(a["id"], (0, 0))[1], "error": drive.errors.get(a["id"])}
                for a in store.accounts(include_disabled=False)]
        return {"accounts": rows, "used": store.total_size(),
                "stored": sum(r["stored"] for r in rows),
                "last_backup": float(store.get("last_snapshot", "0") or 0)}

    @app.patch("/api/accounts/{account_id}")
    async def rename_account(account_id: int, request: Request, body: dict = Body(...)):
        require_login(request)
        label = str(body.get("label", "")).strip()[:30]
        if not label:
            raise HTTPException(400, "invalid label")
        if not store.rename_account(account_id, label):
            raise HTTPException(404, "not found")
        return {"ok": True}

    @app.post("/api/accounts/{account_id}/evacuate")
    async def evacuate(account_id: int, request: Request):
        require_login(request)
        if not store.account(account_id):
            raise HTTPException(404, "not found")
        return {"moved": await drive.evacuate(account_id)}

    @app.delete("/api/accounts/{account_id}")
    async def unlink_account(account_id: int, request: Request, force: bool = False):
        require_login(request)
        if not store.account(account_id):
            raise HTTPException(404, "not found")
        parts = store.account_usage().get(account_id, (0, 0))[1]
        if parts and not force:
            raise HTTPException(409, f"{parts} file parts are stored in this account. Move them "
                                     "to your other accounts first, or unlink anyway.")
        if tg is not None:
            await tg.detach(account_id)
        store.delete_account(account_id)
        drive.errors.pop(account_id, None)
        return {"ok": True}

    # -- files ---------------------------------------------------------------------------------
    @app.get("/api/files")
    async def list_files(request: Request, path: str = "/"):
        require_login(request)
        entries = await drive.ls(path)
        return {"path": join(split(path)), "entries": [e.to_dict() for e in entries],
                "errors": [{"account": drive.label(i), "error": err} for i, err in drive.errors.items()]}

    @app.get("/api/search")
    async def search(request: Request, q: str = ""):
        require_login(request)
        return {"results": await drive.search(q)}

    @app.get("/api/download")
    async def download(request: Request, path: str, inline: bool = False):
        require_login(request)
        entry, dl = await drive.read(path, request.headers.get("range"))
        return stream_response(entry, dl, inline)

    @app.post("/api/upload")
    async def upload(request: Request, path: str = Form("/"), files: list[UploadFile] = File(...),
                     relpaths: Optional[list[str]] = Form(None)):
        require_login(request)
        base = split(path)
        done = []
        for i, f in enumerate(files):
            rel = relpaths[i] if relpaths and i < len(relpaths) and relpaths[i] else f.filename
            parts = split(rel or "upload")
            if len(parts) > 1:
                await drive.makedirs(join(base + parts[:-1]))
            f.file.seek(0, 2)
            size = f.file.tell()
            f.file.seek(0)
            entry = await drive.write(join(base + parts), f.file, size, f.content_type)
            done.append(entry.to_dict())
        return {"uploaded": done}

    @app.post("/api/mkdir")
    async def mkdir(request: Request, body: dict = Body(...)):
        require_login(request)
        return (await drive.mkdir(str(body.get("path", "")))).to_dict()

    @app.post("/api/move")
    async def move(request: Request, body: dict = Body(...)):
        require_login(request)
        src, dst = join(split(str(body["src"]))), join(split(str(body["dst"])))
        entry = await drive.move(src, dst, bool(body.get("overwrite")))
        store.delete_props(dst)
        store.copy_props(src, dst, move=True)  # keep WebDAV properties with the item
        return entry.to_dict()

    @app.post("/api/copy")
    async def copy(request: Request, body: dict = Body(...)):
        require_login(request)
        return (await drive.copy(str(body["src"]), str(body["dst"]), bool(body.get("overwrite")))).to_dict()

    @app.post("/api/delete")
    async def delete(request: Request, body: dict = Body(...)):
        require_login(request)
        for p in body.get("paths", []):
            path = join(split(str(p)))
            await drive.delete(path)
            store.delete_props(path)
        return {"ok": True}

    # -- share links ---------------------------------------------------------------------------
    @app.post("/api/share")
    async def share(request: Request, body: dict = Body(...)):
        require_login(request)
        entry = await drive.stat(str(body.get("path", "")))
        if entry.is_dir:
            raise HTTPException(400, "only files can be shared")
        days = max(1, min(30, int(body.get("days", 7))))
        token = secrets.token_urlsafe(24)
        store.add_share(token_hash(token), entry.id, time.time() + days * 86400)
        return {"links": [{"account": f"expires in {days} day{'s' if days > 1 else ''}",
                           "link": f"{settings.base_url}/s/{token}"}]}

    @app.get("/api/shares")
    async def list_shares(request: Request):
        require_login(request)
        out = []
        for s in store.shares():
            path = store.path_of(s["node_id"])
            if path:
                out.append({"id": s["token_hash"][:16], "path": path, "expires": s["expires"]})
        return out

    @app.delete("/api/shares/{sid}")
    async def revoke_share(sid: str, request: Request):
        require_login(request)
        for s in store.shares():
            if s["token_hash"].startswith(sid) and len(sid) >= 16:
                store.delete_share(s["token_hash"])
                return {"ok": True}
        raise HTTPException(404, "not found")

    @app.get("/s/{token}", include_in_schema=False)
    async def shared_file(token: str, request: Request, inline: bool = False):
        share_row = store.share(token_hash(token))
        path = store.path_of(share_row["node_id"]) if share_row else None
        if not path:
            raise HTTPException(404, "this link is invalid or has expired")
        entry, dl = await drive.read(path, request.headers.get("range"))
        resp = stream_response(entry, dl, inline)
        resp.headers["X-Robots-Tag"] = "noindex"
        return resp

    # -- WebDAV -----------------------------------------------------------------------------------
    dav = WebDAV(drive, "/dav", dav_auth, props=store)  # type: ignore[arg-type]
    methods = ["GET", "HEAD", "PUT", "DELETE", "OPTIONS", "PROPFIND", "PROPPATCH", "MKCOL",
               "COPY", "MOVE", "LOCK", "UNLOCK"]
    app.add_api_route("/dav", dav, methods=methods, include_in_schema=False)
    app.add_api_route("/dav/{rest:path}", dav, methods=methods, include_in_schema=False)
    return app
