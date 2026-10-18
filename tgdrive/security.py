"""Password hashing, TOTP (RFC 6238), token encryption and login throttling.

Only the standard library and ``cryptography`` are used.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from collections import defaultdict, deque
from typing import Optional
from urllib.parse import quote

from cryptography.fernet import Fernet, InvalidToken

# -- passwords (scrypt) ----------------------------------------------------------
_N, _R, _P = 2**15, 8, 1


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, maxmem=64 * 1024 * 1024)
    return f"scrypt${_N}${_R}${_P}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, n, r, p, salt, dk = stored.split("$")
        got = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r),
                             p=int(p), maxmem=64 * 1024 * 1024)
        return hmac.compare_digest(got.hex(), dk)
    except (ValueError, TypeError):
        return False


# -- TOTP ------------------------------------------------------------------------
def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def totp(secret: str, at: Optional[float] = None, step: int = 30, digits: int = 6) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    counter = int((time.time() if at is None else at) // step)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 10**digits
    return str(code).zfill(digits)


def verify_totp(secret: str, code: str, window: int = 1, at: Optional[float] = None) -> bool:
    code = (code or "").strip().replace(" ", "")
    if not code.isdigit():
        return False
    now = time.time() if at is None else at
    return any(hmac.compare_digest(totp(secret, now + i * 30), code)
               for i in range(-window, window + 1))


def totp_uri(secret: str, account: str, issuer: str = "Telegram Drive") -> str:
    return (f"otpauth://totp/{quote(issuer)}:{quote(account)}?secret={secret}"
            f"&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30")


# -- encryption of refresh tokens at rest -------------------------------------------
class Vault:
    def __init__(self, secret_key: str):
        key = hashlib.sha256(("drivehub-vault:" + secret_key).encode()).digest()
        self._f = Fernet(base64.urlsafe_b64encode(key))

    def seal(self, plaintext: str) -> str:
        return self._f.encrypt(plaintext.encode()).decode()

    def open(self, token: str) -> str:
        try:
            return self._f.decrypt(token.encode()).decode()
        except InvalidToken as e:
            raise ValueError("cannot decrypt stored token; was DRIVEHUB_SECRET_KEY changed?") from e


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# -- brute-force protection ----------------------------------------------------------
class Throttle:
    """Allow ``limit`` failures per ``window`` seconds per key (IP address)."""

    def __init__(self, limit: int = 10, window: float = 900):
        self.limit, self.window = limit, window
        self._fails: dict[str, deque[float]] = defaultdict(deque)

    def _prune(self, key: str) -> deque[float]:
        q = self._fails[key]
        cutoff = time.monotonic() - self.window
        while q and q[0] < cutoff:
            q.popleft()
        return q

    def blocked(self, key: str) -> bool:
        return len(self._prune(key)) >= self.limit

    def fail(self, key: str) -> None:
        if len(self._fails) > 10_000:  # forget idle keys so memory stays bounded
            for k in [k for k in self._fails if not self._prune(k)]:
                del self._fails[k]
        self._prune(key).append(time.monotonic())

    def reset(self, key: str) -> None:
        self._fails.pop(key, None)
