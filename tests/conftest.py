import asyncio
import base64

import pytest
from fastapi.testclient import TestClient

from tgdrive import crypto
from tgdrive.app import create_app
from tgdrive.config import Settings
from tgdrive.fake import FakeTelegram
from tgdrive.security import Vault, hash_password
from tgdrive.store import Store

PASSWORD = "correct horse battery"
H = {"X-TgDrive": "1"}


@pytest.fixture
def make_client(tmp_path):
    def make(password=PASSWORD, vault_ready=True, accounts=2, tg=None):
        settings = Settings(data_dir=tmp_path, base_url="http://testserver", telegram_api_id=1,
                            telegram_api_hash="x", secret_key="test-secret", chunk_mb=16)
        store = Store(tmp_path / "t.db")
        tg = tg or FakeTelegram()
        vault = Vault(settings.secret_key)
        if password:
            store.set("password_hash", hash_password(password))
        if vault_ready:
            store.set("master_sealed", vault.seal(base64.b64encode(b"m" * 32).decode()))
        for i in range(accounts):
            tg.add_user(f"+4470000000{i}", f"Person {i}")
            res = asyncio.run(tg.submit_code(asyncio.run(tg.start_login(f"+4470000000{i}")).login_id, "12345"))
            store.upsert_account(res.user.id, res.user.phone, res.user.name, f"acc{i}", vault.seal(res.session))
        app = create_app(settings, store, tg)
        app.state.tg = tg
        return TestClient(app)
    return make


@pytest.fixture
def client(make_client):
    with make_client() as c:
        r = c.post("/api/login", json={"password": PASSWORD}, headers=H)
        assert r.status_code == 200, r.text
        c.headers.update(H)
        yield c
