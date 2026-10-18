import base64
from xml.etree import ElementTree as ET

import pytest

D = "{DAV:}"


@pytest.fixture
def dav(client):
    pw = client.post("/api/app-passwords", json={"name": "laptop"}).json()["password"]
    client.post("/api/logout")
    client.cookies.clear()
    token = base64.b64encode(f"me:{pw}".encode()).decode()
    client.headers["Authorization"] = f"Basic {token}"
    return client


def propfind(c, path, depth="1"):
    r = c.request("PROPFIND", path, headers={"Depth": depth})
    assert r.status_code == 207, r.text
    root = ET.fromstring(r.content)
    out = {}
    for resp in root.findall(f"{D}response"):
        href = resp.find(f"{D}href").text
        prop = resp.find(f"{D}propstat/{D}prop")
        out[href] = prop
    return out


def test_requires_auth(make_client):
    with make_client() as c:
        r = c.request("PROPFIND", "/dav/")
        assert r.status_code == 401 and "Basic" in r.headers["www-authenticate"]
        bad = base64.b64encode(b"me:wrong").decode()
        assert c.request("PROPFIND", "/dav/", headers={"Authorization": f"Basic {bad}"}).status_code == 401
        assert c.options("/dav/").headers["dav"] == "1, 2"


def test_put_get_propfind(dav):
    assert dav.put("/dav/hello.txt", content=b"hi there").status_code == 201
    assert dav.put("/dav/hello.txt", content=b"hi again").status_code == 204
    assert dav.get("/dav/hello.txt").content == b"hi again"
    r = dav.get("/dav/hello.txt", headers={"Range": "bytes=0-1"})
    assert r.status_code == 206 and r.content == b"hi"
    props = propfind(dav, "/dav/")
    assert "/dav/" in props and "/dav/hello.txt" in props
    root = props["/dav/"]
    assert root.find(f"{D}resourcetype/{D}collection") is not None
    assert int(root.find(f"{D}quota-available-bytes").text) > 0
    assert props["/dav/hello.txt"].find(f"{D}getcontentlength").text == "8"
    head = dav.head("/dav/hello.txt")
    assert head.status_code == 200 and head.headers["content-length"] == "8"


def test_mkcol_move_copy_delete(dav):
    assert dav.request("MKCOL", "/dav/Docs").status_code == 201
    assert dav.request("MKCOL", "/dav/Docs").status_code == 405
    assert dav.request("MKCOL", "/dav/missing/child").status_code == 409
    dav.put("/dav/Docs/a.txt", content=b"a")
    r = dav.request("MOVE", "/dav/Docs/a.txt",
                    headers={"Destination": "http://testserver/dav/Docs/b%20file.txt"})
    assert r.status_code == 201
    r = dav.request("COPY", "/dav/Docs", headers={"Destination": "http://testserver/dav/Docs2"})
    assert r.status_code == 201
    assert "/dav/Docs2/b%20file.txt" in propfind(dav, "/dav/Docs2")
    dav.put("/dav/x.txt", content=b"x")
    r = dav.request("MOVE", "/dav/x.txt", headers={"Destination": "http://testserver/dav/Docs2/b%20file.txt",
                                                   "Overwrite": "F"})
    assert r.status_code == 412
    assert dav.delete("/dav/Docs").status_code == 204
    assert dav.get("/dav/Docs/b%20file.txt").status_code == 404


def test_lock_unlock_proppatch(dav):
    r = dav.request("LOCK", "/dav/new.docx", content=b'<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:">'
                    b'<D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype>'
                    b'<D:owner>me</D:owner></D:lockinfo>')
    assert r.status_code == 201 and r.headers["lock-token"].startswith("<opaquelocktoken:")
    assert dav.request("UNLOCK", "/dav/new.docx", headers={"Lock-Token": r.headers["lock-token"]}).status_code == 204
    r = dav.request("PROPPATCH", "/dav/new.docx", content=b'<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:" '
                    b'xmlns:Z="urn:schemas-microsoft-com:"><D:set><D:prop><Z:Win32LastModifiedTime>x'
                    b'</Z:Win32LastModifiedTime></D:prop></D:set></D:propertyupdate>')
    assert r.status_code == 207


def test_folder_listing_html_is_escaped(dav):
    import urllib.parse
    name = "<img src=x onerror=alert(1)>.txt"
    assert dav.put("/dav/" + urllib.parse.quote(name), content=b"x").status_code == 201
    body = dav.get("/dav/").text
    assert "<img src=x" not in body and "&lt;img" in body


def test_revoked_app_password(client):
    created = client.post("/api/app-passwords", json={"name": "phone"}).json()
    client.delete(f"/api/app-passwords/{created['id']}")
    token = base64.b64encode(f"me:{created['password']}".encode()).decode()
    client.cookies.clear()
    assert client.request("PROPFIND", "/dav/", headers={"Authorization": f"Basic {token}"}).status_code == 401


def test_locks_are_enforced(dav):
    dav.put("/dav/locked.txt", content=b"v1")
    r = dav.request("LOCK", "/dav/locked.txt", content=b'<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:">'
                    b'<D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockinfo>')
    token = r.headers["lock-token"]
    assert dav.put("/dav/locked.txt", content=b"v2").status_code == 423
    assert dav.delete("/dav/locked.txt").status_code == 423
    assert dav.put("/dav/locked.txt", content=b"v2", headers={"If": f"({token})"}).status_code == 204
    assert dav.request("UNLOCK", "/dav/locked.txt", headers={"Lock-Token": "<opaquelocktoken:bogus>"}).status_code == 409
    assert dav.request("UNLOCK", "/dav/locked.txt", headers={"Lock-Token": token}).status_code == 204
    assert dav.delete("/dav/locked.txt").status_code == 204


def test_dead_properties_roundtrip(dav):
    dav.put("/dav/p.txt", content=b"p")
    body = (b'<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:x">'
            b'<D:set><D:prop><Z:color>blue</Z:color></D:prop></D:set></D:propertyupdate>')
    assert dav.request("PROPPATCH", "/dav/p.txt", content=body).status_code == 207
    dav.request("MOVE", "/dav/p.txt", headers={"Destination": "http://testserver/dav/q.txt"})
    r = dav.request("PROPFIND", "/dav/q.txt", headers={"Depth": "0"},
                    content=b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:" xmlns:Z="urn:x">'
                            b'<D:prop><Z:color/><Z:missing/></D:prop></D:propfind>')
    root = ET.fromstring(r.content)
    statuses = {ps.find(f"{D}status").text: [c.tag for c in ps.find(f"{D}prop")]
                for ps in root.iter(f"{D}propstat")}
    assert statuses["HTTP/1.1 200 OK"] == ["{urn:x}color"]
    assert statuses["HTTP/1.1 404 Not Found"] == ["{urn:x}missing"]
    protected = (b'<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:"><D:set><D:prop>'
                 b'<D:getetag>x</D:getetag></D:prop></D:set></D:propertyupdate>')
    assert b"403 Forbidden" in dav.request("PROPPATCH", "/dav/q.txt", content=protected).content


def test_special_characters_in_names(dav):
    from urllib.parse import quote
    name = "50% off #1? ünï"
    assert dav.request("MKCOL", "/dav/" + quote(name)).status_code == 201
    assert dav.put("/dav/" + quote(name) + "/a%2520b.txt", content=b"x").status_code == 201
    props = propfind(dav, "/dav/" + quote(name))
    assert "/dav/" + quote(name) + "/a%2520b.txt" in props  # literal "a%20b.txt"
