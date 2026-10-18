"""Telegram access: web login (code + 2FA) and Saved Messages as a file store.

``TelegramAPI`` is the small surface the rest of the app uses. ``TelethonAPI``
talks to real Telegram through Telethon (MTProto, as a normal user client);
``FakeTelegram`` in fake.py implements the same surface in memory for tests and
the demo.
"""
from __future__ import annotations

import asyncio
import io
import logging
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, BinaryIO, Optional, Protocol

log = logging.getLogger("tgdrive.telegram")
LOGIN_TTL = 600  # seconds a half-finished login stays valid
MAX_FLOOD_WAIT = 900


class TelegramError(Exception):
    def __init__(self, message: str, status: int = 502):
        super().__init__(message)
        self.status = status


@dataclass
class TgUser:
    id: int
    phone: str
    name: str


@dataclass
class LoginResult:
    status: str  # "code_sent" | "password_needed" | "ok"
    login_id: str = ""
    user: Optional[TgUser] = None
    session: str = ""
    hint: str = ""


@dataclass
class TaggedMessage:
    message_id: int
    text: str
    date: float
    size: Optional[int]


class TelegramAPI(Protocol):
    async def start_login(self, phone: str) -> LoginResult: ...
    async def submit_code(self, login_id: str, code: str) -> LoginResult: ...
    async def submit_password(self, login_id: str, password: str) -> LoginResult: ...
    async def attach(self, account_id: int, session: str) -> None: ...
    async def detach(self, account_id: int) -> None: ...
    async def whoami(self, account_id: int) -> TgUser: ...
    async def upload(self, account_id: int, data: BinaryIO, size: int, file_name: str,
                     caption: str) -> int: ...
    def download(self, account_id: int, message_id: int, offset: int,
                 length: int) -> AsyncIterator[bytes]: ...
    async def delete(self, account_id: int, message_ids: list[int]) -> None: ...
    def iter_tagged(self, account_id: int, tag: str) -> AsyncIterator[TaggedMessage]: ...
    async def close(self) -> None: ...


def normalize_phone(phone: str) -> str:
    digits = "".join(ch for ch in phone if ch.isdigit())
    if len(digits) < 7 or len(digits) > 15:
        raise TelegramError("enter the phone number in international format, e.g. +91 98765 43210", 400)
    return "+" + digits


# -- real Telegram ---------------------------------------------------------------------

@dataclass
class _PendingLogin:
    client: Any
    phone: str
    phone_code_hash: str
    created: float = field(default_factory=time.time)
    attempts: int = 0


class TelethonAPI:
    """Real Telegram via Telethon. Each linked account keeps one connected client."""

    def __init__(self, api_id: int, api_hash: str, device: str = "Telegram Drive"):
        if not api_id or not api_hash:
            raise TelegramError("TELEGRAM_API_ID and TELEGRAM_API_HASH are not set", 400)
        self.api_id, self.api_hash, self.device = int(api_id), api_hash, device
        self._clients: dict[int, Any] = {}
        self._sessions: dict[int, str] = {}
        self._pending: dict[str, _PendingLogin] = {}
        self._locks: dict[int, asyncio.Lock] = {}

    def _new_client(self, session: str = ""):
        from telethon import TelegramClient
        from telethon.sessions import StringSession
        return TelegramClient(StringSession(session), self.api_id, self.api_hash,
                              device_model=self.device, app_version="0.1",
                              flood_sleep_threshold=60, connection_retries=5,
                              request_retries=5, auto_reconnect=True)

    # -- login ----------------------------------------------------------------------------
    def _purge(self) -> None:
        now = time.time()
        for lid in [k for k, p in self._pending.items() if now - p.created > LOGIN_TTL]:
            p = self._pending.pop(lid)
            asyncio.ensure_future(p.client.disconnect())

    async def start_login(self, phone: str) -> LoginResult:
        from telethon import errors
        self._purge()
        phone = normalize_phone(phone)
        client = self._new_client()
        try:
            await client.connect()
            sent = await client.send_code_request(phone)
        except BaseException as e:
            await client.disconnect()
            if isinstance(e, errors.PhoneNumberInvalidError):
                raise TelegramError("Telegram says this phone number is invalid", 400) from e
            if isinstance(e, errors.PhoneNumberBannedError):
                raise TelegramError("Telegram has banned this phone number", 403) from e
            if isinstance(e, errors.FloodWaitError):
                raise TelegramError(f"Too many attempts; Telegram asks to wait {e.seconds} s", 429) from e
            if isinstance(e, errors.RPCError):
                raise TelegramError(f"Telegram refused the login: {e}", 400) from e
            if isinstance(e, (ConnectionError, OSError, asyncio.TimeoutError)):
                raise TelegramError(f"cannot reach Telegram: {e}", 503) from e
            raise
        login_id = secrets.token_urlsafe(16)
        self._pending[login_id] = _PendingLogin(client, phone, sent.phone_code_hash)
        return LoginResult("code_sent", login_id)

    def _get_pending(self, login_id: str) -> _PendingLogin:
        self._purge()
        p = self._pending.get(login_id)
        if p is None:
            raise TelegramError("this login expired; start again", 410)
        p.attempts += 1
        if p.attempts > 6:
            self._pending.pop(login_id, None)
            asyncio.ensure_future(p.client.disconnect())
            raise TelegramError("too many wrong attempts; start again", 429)
        return p

    async def _finish(self, login_id: str, p: _PendingLogin) -> LoginResult:
        me = await p.client.get_me()
        session = p.client.session.save()
        self._pending.pop(login_id, None)
        await p.client.disconnect()
        name = " ".join(x for x in (me.first_name, me.last_name) if x) or (me.username or "")
        return LoginResult("ok", login_id, TgUser(me.id, "+" + (me.phone or "").lstrip("+"), name),
                           session)

    async def submit_code(self, login_id: str, code: str) -> LoginResult:
        from telethon import errors
        p = self._get_pending(login_id)
        try:
            await p.client.sign_in(phone=p.phone, code=code.strip().replace(" ", ""),
                                   phone_code_hash=p.phone_code_hash)
        except errors.SessionPasswordNeededError:
            hint = ""
            try:
                from telethon.tl.functions.account import GetPasswordRequest
                hint = (await p.client(GetPasswordRequest())).hint or ""
            except Exception:
                pass
            return LoginResult("password_needed", login_id, hint=hint)
        except (errors.PhoneCodeInvalidError, errors.PhoneCodeEmptyError) as e:
            raise TelegramError("that code is not correct", 400) from e
        except errors.PhoneCodeExpiredError as e:
            self._pending.pop(login_id, None)
            await p.client.disconnect()
            raise TelegramError("the code expired; start again", 410) from e
        except errors.RPCError as e:
            raise TelegramError(f"Telegram refused the login: {e}", 400) from e
        return await self._finish(login_id, p)

    async def submit_password(self, login_id: str, password: str) -> LoginResult:
        from telethon import errors
        p = self._get_pending(login_id)
        try:
            await p.client.sign_in(password=password)
        except errors.PasswordHashInvalidError as e:
            raise TelegramError("that Telegram password is not correct", 400) from e
        except errors.RPCError as e:
            raise TelegramError(f"Telegram refused the login: {e}", 400) from e
        return await self._finish(login_id, p)

    # -- linked accounts --------------------------------------------------------------------
    async def attach(self, account_id: int, session: str) -> None:
        self._sessions[account_id] = session

    async def detach(self, account_id: int) -> None:
        self._sessions.pop(account_id, None)
        client = self._clients.pop(account_id, None)
        if client is not None:
            await client.disconnect()

    async def _client(self, account_id: int):
        lock = self._locks.setdefault(account_id, asyncio.Lock())
        async with lock:
            client = self._clients.get(account_id)
            if client is not None and client.is_connected():
                return client
            if client is None:
                session = self._sessions.get(account_id)
                if session is None:
                    raise TelegramError("account is not linked", 404)
                # one client per session: two connections on one auth key can get it revoked
                client = self._new_client(session)
            try:
                await client.connect()
            except (ConnectionError, OSError, asyncio.TimeoutError) as e:
                raise TelegramError(f"cannot reach Telegram: {e}", 503) from e
            if not await client.is_user_authorized():
                await client.disconnect()
                raise TelegramError("Telegram signed this session out; link the account again", 401)
            self._clients[account_id] = client
            return client

    async def _retry(self, fn, *args, **kw):
        from telethon import errors
        for attempt in range(4):
            try:
                return await fn(*args, **kw)
            except errors.FloodWaitError as e:
                if e.seconds > MAX_FLOOD_WAIT or attempt == 3:
                    raise TelegramError(f"Telegram rate limit: wait {e.seconds} s", 429) from e
                log.warning("flood wait %ss", e.seconds)
                await asyncio.sleep(e.seconds + 1)
            except (errors.AuthKeyUnregisteredError, errors.SessionRevokedError,
                    errors.UserDeactivatedError) as e:
                raise TelegramError("Telegram signed this session out; link the account again", 401) from e
            except (ConnectionError, OSError, asyncio.TimeoutError) as e:
                if attempt == 3:
                    raise TelegramError(f"cannot reach Telegram: {e}", 503) from e
                await asyncio.sleep(2 ** attempt)
            except errors.RPCError as e:
                raise TelegramError(f"Telegram error: {e}", 502) from e

    async def whoami(self, account_id: int) -> TgUser:
        client = await self._client(account_id)
        me = await self._retry(client.get_me)
        name = " ".join(x for x in (me.first_name, me.last_name) if x) or (me.username or "")
        return TgUser(me.id, "+" + (me.phone or "").lstrip("+"), name)

    async def upload(self, account_id: int, data: BinaryIO, size: int, file_name: str,
                     caption: str) -> int:
        client = await self._client(account_id)

        async def go():
            data.seek(0)
            handle = await client.upload_file(data, file_size=size, file_name=file_name,
                                              part_size_kb=512)
            msg = await client.send_file("me", handle, caption=caption, force_document=True,
                                         parse_mode=None)
            return msg.id
        return await self._retry(go)

    async def download(self, account_id: int, message_id: int, offset: int,
                       length: int) -> AsyncIterator[bytes]:
        client = await self._client(account_id)
        msg = await self._retry(client.get_messages, "me", ids=message_id)
        if msg is None or msg.document is None:
            raise TelegramError("a stored part is missing from Saved Messages", 404)
        from telethon import errors
        remaining = length
        try:
            # 512 KiB is the largest request size Telegram allows for file downloads
            async for part in client.iter_download(msg.document, offset=offset,
                                                   request_size=512 * 1024,
                                                   file_size=msg.document.size):
                part = bytes(part[:remaining])
                remaining -= len(part)
                yield part
                if remaining <= 0:
                    break
        except errors.FloodWaitError as e:
            raise TelegramError(f"Telegram rate limit: wait {e.seconds} s", 429) from e
        except (errors.AuthKeyUnregisteredError, errors.SessionRevokedError) as e:
            raise TelegramError("Telegram signed this session out; link the account again", 401) from e
        except errors.RPCError as e:
            raise TelegramError(f"Telegram error: {e}", 502) from e
        except (ConnectionError, OSError, asyncio.TimeoutError) as e:
            raise TelegramError(f"cannot reach Telegram: {e}", 503) from e
        if remaining > 0:
            raise TelegramError("download ended early", 502)

    async def delete(self, account_id: int, message_ids: list[int]) -> None:
        if not message_ids:
            return
        client = await self._client(account_id)
        for i in range(0, len(message_ids), 100):
            await self._retry(client.delete_messages, "me", message_ids[i:i + 100], revoke=True)

    async def iter_tagged(self, account_id: int, tag: str) -> AsyncIterator[TaggedMessage]:
        from telethon.tl.types import InputMessagesFilterDocument
        client = await self._client(account_id)
        # Walk the documents in Saved Messages; captions are matched locally because
        # Telegram's text search tokenizes and would not match a prefix reliably.
        async for m in client.iter_messages("me", filter=InputMessagesFilterDocument):
            text = m.message or ""
            if text.startswith(tag):
                yield TaggedMessage(m.id, text, m.date.timestamp(),
                                    m.document.size if m.document else None)

    async def close(self) -> None:
        for aid in list(self._clients):
            await self.detach(aid)
        for p in self._pending.values():
            await p.client.disconnect()
        self._pending.clear()


def as_stream(data: bytes) -> io.BytesIO:
    return io.BytesIO(data)
