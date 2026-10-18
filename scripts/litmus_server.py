"""Demo server with a fixed WebDAV app password, used by CI to run litmus."""
import asyncio
import sys
import tempfile
from pathlib import Path

import uvicorn

from tgdrive.app import create_app
from tgdrive.config import Settings
from tgdrive.demo import populate
from tgdrive.fake import FakeTelegram
from tgdrive.security import Vault, hash_password, token_hash
from tgdrive.store import Store

port = int(sys.argv[1]) if len(sys.argv) > 1 else 8099
tmp = Path(tempfile.mkdtemp())
settings = Settings(tmp, f"http://127.0.0.1:{port}", 1, "ci", "ci-secret", demo=True, chunk_mb=16)
store = Store(tmp / "tgdrive.db")
tg = FakeTelegram()
asyncio.run(populate(store, tg, Vault(settings.secret_key), settings.chunk_mb))
store.set("password_hash", hash_password("demo-password"))
store.add_app_password("litmus", token_hash("litmus-app-password"))
uvicorn.run(create_app(settings, store, tg), host="127.0.0.1", port=port, log_level="warning")
