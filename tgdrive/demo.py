"""Sample content for ``tgdrive demo``: two fake Telegram accounts with files in them."""
from __future__ import annotations

import base64
import io
import random
import struct
import zlib

from . import crypto
from .drive import Drive
from .fake import FakeTelegram
from .security import Vault
from .store import Store


def _png(w: int, h: int, rgb: tuple[int, int, int]) -> bytes:
    raw = b"".join(b"\x00" + bytes(rgb) * w for _ in range(h))

    def chunk(kind: bytes, data: bytes) -> bytes:
        return (struct.pack(">I", len(data)) + kind + data
                + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


async def populate(store: Store, tg: FakeTelegram, vault: Vault, chunk_mb: int) -> None:
    master = crypto.new_master_key()
    store.set("master_sealed", vault.seal(base64.b64encode(master).decode()))
    for phone, name in (("+1 555 0001", "Asha Personal"), ("+1 555 0002", "Asha Work")):
        tg.add_user(phone, name)
        res = await tg.submit_code((await tg.start_login(phone)).login_id, "12345")
        aid = store.upsert_account(res.user.id, res.user.phone, res.user.name, name.split()[1],
                                   vault.seal(res.session))
        await tg.attach(aid, res.session)
    tg.add_user("+1 555 0100", "Extra Account")
    tg.add_user("+1 555 0101", "Protected Account", password="demo-telegram")
    drive = Drive(store, tg, chunk_size=chunk_mb * 1024 * 1024)
    drive.unlock(master)
    await drive.makedirs("/Photos/2026 Goa trip")
    await drive.makedirs("/Documents")
    await drive.makedirs("/Videos")
    for name, rgb in (("beach.png", (40, 140, 200)), ("sunset.png", (230, 120, 40))):
        data = _png(320, 200, rgb)
        await drive.write(f"/Photos/2026 Goa trip/{name}", io.BytesIO(data), len(data), "image/png")
    note = b"Telegram Drive demo\n\nEverything here is encrypted before it reaches Telegram.\n"
    await drive.write("/Documents/readme.txt", io.BytesIO(note), len(note), "text/plain")
    big = random.Random(7).randbytes(40 * 1024 * 1024)
    await drive.write("/Videos/big-file.bin", io.BytesIO(big), len(big))
    await drive.snapshot()
