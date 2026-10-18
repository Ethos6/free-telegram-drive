"""In-memory Telegram used by the test suite and ``tgdrive demo``.

It follows the real flow closely: a login code (always 12345) is "sent", an
account can have a 2FA password, Saved Messages hold documents with captions,
captions are searchable, and downloads honour byte offsets.
"""
from __future__ import annotations

import asyncio
import itertools
import secrets
import time
from dataclasses import dataclass, field
from typing import AsyncIterator, BinaryIO, Optional

from .telegram import LoginResult, TaggedMessage, TelegramError, TgUser, normalize_phone

CODE = "12345"


@dataclass
class FakeMessage:
    id: int
    data: bytes
    caption: str
    file_name: str
    date: float = field(default_factory=time.time)


@dataclass
class FakeAccount:
    user: TgUser
    password: Optional[str] = None
    messages: dict[int, FakeMessage] = field(default_factory=dict)
    ids: itertools.count = field(default_factory=lambda: itertools.count(1))
    sessions: set[str] = field(default_factory=set)


class FakeTelegram:
    def __init__(self, max_file: int = 2000 * 1024 * 1024):
        self.accounts: dict[str, FakeAccount] = {}  # by phone
        self.attached: dict[int, str] = {}  # account_id -> session
        self.pending: dict[str, str] = {}  # login_id -> phone
        self.max_file = max_file
        self.fail_uploads = 0  # make the next N uploads fail (tests)
        self.calls: list[str] = []

    # helpers for tests/demo
    def add_user(self, phone: str, name: str, password: Optional[str] = None) -> FakeAccount:
        phone = normalize_phone(phone)
        acc = FakeAccount(TgUser(1000 + len(self.accounts), phone, name), password)
        self.accounts[phone] = acc
        return acc

    def _by_session(self, account_id: int) -> FakeAccount:
        session = self.attached.get(account_id)
        for acc in self.accounts.values():
            if session in acc.sessions:
                return acc
        raise TelegramError("Telegram signed this session out; link the account again", 401)

    # login
    async def start_login(self, phone: str) -> LoginResult:
        phone = normalize_phone(phone)
        if phone not in self.accounts:
            raise TelegramError("Telegram says this phone number is invalid", 400)
        login_id = secrets.token_urlsafe(8)
        self.pending[login_id] = phone
        return LoginResult("code_sent", login_id)

    def _finish(self, login_id: str) -> LoginResult:
        acc = self.accounts[self.pending.pop(login_id)]
        session = "fake-session-" + secrets.token_hex(8)
        acc.sessions.add(session)
        return LoginResult("ok", login_id, acc.user, session)

    async def submit_code(self, login_id: str, code: str) -> LoginResult:
        phone = self.pending.get(login_id)
        if phone is None:
            raise TelegramError("this login expired; start again", 410)
        if code.strip() != CODE:
            raise TelegramError("that code is not correct", 400)
        if self.accounts[phone].password:
            self.pending["pw:" + login_id] = phone
            return LoginResult("password_needed", login_id, hint="demo")
        return self._finish(login_id)

    async def submit_password(self, login_id: str, password: str) -> LoginResult:
        phone = self.pending.get("pw:" + login_id)
        if phone is None:
            raise TelegramError("this login expired; start again", 410)
        if password != self.accounts[phone].password:
            raise TelegramError("that Telegram password is not correct", 400)
        self.pending.pop("pw:" + login_id)
        return self._finish(login_id)

    # storage
    async def attach(self, account_id: int, session: str) -> None:
        self.attached[account_id] = session

    async def detach(self, account_id: int) -> None:
        self.attached.pop(account_id, None)

    async def whoami(self, account_id: int) -> TgUser:
        return self._by_session(account_id).user

    async def upload(self, account_id: int, data: BinaryIO, size: int, file_name: str,
                     caption: str) -> int:
        acc = self._by_session(account_id)
        self.calls.append(f"upload:{account_id}")
        if self.fail_uploads:
            self.fail_uploads -= 1
            raise TelegramError("cannot reach Telegram: simulated failure", 503)
        if size > self.max_file:
            raise TelegramError("file too big for Telegram", 400)
        if len(caption) > 1024:
            raise TelegramError("caption too long", 400)
        data.seek(0)
        content = data.read()
        assert len(content) == size, (len(content), size)
        await asyncio.sleep(0)
        mid = next(acc.ids)
        acc.messages[mid] = FakeMessage(mid, content, caption, file_name)
        return mid

    async def download(self, account_id: int, message_id: int, offset: int,
                       length: int) -> AsyncIterator[bytes]:
        acc = self._by_session(account_id)
        self.calls.append(f"download:{account_id}:{message_id}:{offset}:{length}")
        msg = acc.messages.get(message_id)
        if msg is None:
            raise TelegramError("a stored part is missing from Saved Messages", 404)
        body = msg.data[offset:offset + length]
        for i in range(0, len(body), 1024 * 1024):
            yield body[i:i + 1024 * 1024]
            await asyncio.sleep(0)

    async def delete(self, account_id: int, message_ids: list[int]) -> None:
        acc = self._by_session(account_id)
        for mid in message_ids:
            acc.messages.pop(mid, None)

    async def iter_tagged(self, account_id: int, tag: str) -> AsyncIterator[TaggedMessage]:
        acc = self._by_session(account_id)
        for m in sorted(acc.messages.values(), key=lambda m: -m.id):
            if m.caption.startswith(tag):
                yield TaggedMessage(m.id, m.caption, m.date, len(m.data))

    async def close(self) -> None:
        return None
