import base64
import re

from tgdrive import crypto
from tgdrive.security import totp

from .conftest import H, PASSWORD


def test_first_run_setup_and_vault_creation(make_client):
    with make_client(password=None, vault_ready=False, accounts=0) as c:
        st = c.get("/api/status").json()
        assert st["setup_needed"] and not st["vault_ready"]
        code = c.app.state.setup["setup_token"]
        assert c.post("/api/setup", json={"setup_code": "x", "password": "y" * 12}, headers=H).status_code == 403
        assert c.post("/api/setup", json={"setup_code": code, "password": "long enough pw"}, headers=H).status_code == 200
        c.headers.update(H)
        r = c.post("/api/vault/create")
        key = r.json()["recovery_key"]
        assert re.fullmatch(r"([A-Z2-7]{4}-){13}[A-Z2-7]{4}", key)
        assert c.post("/api/vault/create").status_code == 409
        assert c.get("/api/status").json()["vault_ready"]
        shown = c.post("/api/vault/recovery-key", json={"password": "long enough pw"}).json()
        assert shown["recovery_key"] == key
        assert c.post("/api/vault/recovery-key", json={"password": "nope"}).status_code == 403


def test_restore_with_recovery_key(make_client):
    with make_client(vault_ready=False) as c:
        c.post("/api/login", json={"password": PASSWORD}, headers=H)
        c.headers.update(H)
        assert c.post("/api/vault/restore", json={"recovery_key": "garbage"}).status_code == 400
        key = crypto.format_recovery_key(b"r" * 32)
        assert c.post("/api/vault/restore", json={"recovery_key": key.lower()}).status_code == 200
        assert c.app.state.drive.master == b"r" * 32
        # the key may be replaced while no files are stored, with the password
        other = crypto.format_recovery_key(b"s" * 32)
        assert c.post("/api/vault/restore", json={"recovery_key": other}).status_code == 403
        assert c.post("/api/vault/restore", json={"recovery_key": other, "password": PASSWORD}).status_code == 200
        c.post("/api/upload", data={"path": "/"}, files=[("files", ("a.txt", b"a", "text/plain"))])
        assert c.post("/api/vault/restore", json={"recovery_key": key, "password": PASSWORD}).status_code == 409


def test_files_need_vault(make_client):
    with make_client(vault_ready=False) as c:
        c.post("/api/login", json={"password": PASSWORD}, headers=H)
        c.headers.update(H)
        r = c.post("/api/upload", data={"path": "/"}, files=[("files", ("a.txt", b"a", "text/plain"))])
        assert r.status_code == 409


def test_auth_required_and_csrf_header(make_client):
    with make_client() as c:
        assert c.get("/api/files").status_code == 401
        assert c.post("/api/login", json={"password": PASSWORD}).status_code == 403
        assert c.get("/api/download?path=/x").status_code == 401


def test_login_throttle_and_totp(client):
    s = client.post("/api/totp/setup").json()
    assert client.post("/api/totp/enable", json={"secret": s["secret"], "code": totp(s["secret"])}).status_code == 200
    client.post("/api/logout")
    assert client.post("/api/login", json={"password": PASSWORD}).status_code == 401
    assert client.post("/api/login", json={"password": PASSWORD, "code": totp(s["secret"])}).status_code == 200


def test_telegram_web_login_with_two_step_password(client):
    tg = client.app.state.tg
    tg.add_user("+91 98765 43210", "Ravi Kumar", password="tg-secret")
    r = client.post("/api/telegram/start", json={"phone": "+91 98765 43210"}).json()
    assert r["status"] == "code_sent"
    bad = client.post("/api/telegram/code", json={"login_id": r["login_id"], "code": "00000"})
    assert bad.status_code == 400 and "not correct" in bad.json()["detail"]
    step = client.post("/api/telegram/code", json={"login_id": r["login_id"], "code": "12345"}).json()
    assert step["status"] == "password_needed"
    wrong = client.post("/api/telegram/password", json={"login_id": r["login_id"], "password": "x"})
    assert wrong.status_code == 400
    ok = client.post("/api/telegram/password", json={"login_id": r["login_id"], "password": "tg-secret"}).json()
    assert ok["status"] == "ok" and ok["account"]["name"] == "Ravi Kumar"
    assert "43210" not in ok["account"]["phone"][:-3] and ok["account"]["phone"].endswith("210")
    accounts = client.get("/api/accounts").json()["accounts"]
    assert len(accounts) == 3
    stored = client.app.state.store.accounts()[-1]["session"]
    assert "fake-session" not in stored  # sessions are encrypted at rest


def test_invalid_phone(client):
    r = client.post("/api/telegram/start", json={"phone": "123"})
    assert r.status_code == 400


def test_upload_download_range_share_delete(client):
    data = bytes(range(256)) * 4096  # 1 MiB
    r = client.post("/api/upload", data={"path": "/", "relpaths": ["Music/2026/song.mp3"]},
                    files=[("files", ("song.mp3", data, "audio/mpeg"))])
    assert r.status_code == 200, r.text
    listing = client.get("/api/files", params={"path": "/Music/2026"}).json()["entries"]
    assert [e["name"] for e in listing] == ["song.mp3"] and listing[0]["size"] == len(data)
    full = client.get("/api/download", params={"path": "/Music/2026/song.mp3"})
    assert full.content == data and full.headers["content-disposition"].startswith("attachment")
    part = client.get("/api/download", params={"path": "/Music/2026/song.mp3", "inline": 1},
                      headers={"Range": "bytes=1000-1999"})
    assert part.status_code == 206 and part.content == data[1000:2000]
    assert part.headers["content-range"] == f"bytes 1000-1999/{len(data)}"
    assert part.headers["content-disposition"].startswith("inline")
    link = client.post("/api/share", json={"path": "/Music/2026/song.mp3", "days": 1}).json()["links"][0]["link"]
    token_path = link.replace("http://testserver", "")
    anon = client.__class__(client.app)
    shared = anon.get(token_path)
    assert shared.status_code == 200 and shared.content == data
    shares = client.get("/api/shares").json()
    assert shares[0]["path"] == "/Music/2026/song.mp3"
    assert client.delete(f"/api/shares/{shares[0]['id']}").status_code == 200
    assert anon.get(token_path).status_code == 404
    assert anon.get("/s/forged-token").status_code == 404
    assert client.post("/api/delete", json={"paths": ["/Music"]}).status_code == 200
    assert client.get("/api/files").json()["entries"] == []


def test_html_never_inline(client):
    client.post("/api/upload", data={"path": "/"}, files=[("files", ("x.html", b"<script>alert(1)</script>", "text/html"))])
    r = client.get("/api/download", params={"path": "/x.html", "inline": 1})
    assert r.headers["content-disposition"].startswith("attachment")
    assert "sandbox" in r.headers["content-security-policy"]


def test_move_copy_mkdir_search(client):
    client.post("/api/mkdir", json={"path": "/A"})
    client.post("/api/upload", data={"path": "/A"}, files=[("files", ("note.txt", b"hello", "text/plain"))])
    assert client.post("/api/copy", json={"src": "/A/note.txt", "dst": "/note-copy.txt"}).status_code == 200
    assert client.post("/api/move", json={"src": "/A", "dst": "/B"}).status_code == 200
    names = [e["name"] for e in client.get("/api/files").json()["entries"]]
    assert names == ["B", "note-copy.txt"]
    res = client.get("/api/search", params={"q": "note"}).json()["results"]
    assert {r["path"] for r in res} == {"/B/note.txt", "/note-copy.txt"}


def test_unlink_account_with_parts_requires_move_or_force(client):
    big = b"z" * (40 * 1024 * 1024)
    client.post("/api/upload", data={"path": "/"}, files=[("files", ("big.bin", big, "application/octet-stream"))])
    accounts = client.get("/api/accounts").json()["accounts"]
    first = accounts[0]
    assert first["parts"] > 0
    assert client.delete(f"/api/accounts/{first['id']}").status_code == 409
    moved = client.post(f"/api/accounts/{first['id']}/evacuate").json()["moved"]
    assert moved == first["parts"]
    assert client.delete(f"/api/accounts/{first['id']}").status_code == 200
    assert client.get("/api/download", params={"path": "/big.bin"}).content == big


def test_backup_and_rebuild_endpoints(client):
    client.post("/api/upload", data={"path": "/"}, files=[("files", ("a.txt", b"a", "text/plain"))])
    assert client.post("/api/backup").status_code == 200
    stats = client.post("/api/rebuild").json()
    assert stats["files"] == 1


def test_webdav_ignores_cookie_and_works_with_app_password(client):
    assert client.request("PROPFIND", "/dav/").status_code == 401
    pw = client.post("/api/app-passwords", json={"name": "pc"}).json()["password"]
    auth = {"Authorization": "Basic " + base64.b64encode(f"me:{pw}".encode()).decode()}
    client.cookies.clear()
    assert client.put("/dav/hello.txt", content=b"hi there", headers=auth).status_code == 201
    assert client.get("/dav/hello.txt", headers=auth).content == b"hi there"
    r = client.request("PROPFIND", "/dav/", headers={**auth, "Depth": "0"})
    assert r.status_code == 207 and b"quota-available-bytes" in r.content
    assert b"<D:quota-available-bytes>0<" not in r.content


def test_security_headers_and_pwa(client):
    r = client.get("/")
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert client.get("/manifest.webmanifest").json()["short_name"] == "TG Drive"
