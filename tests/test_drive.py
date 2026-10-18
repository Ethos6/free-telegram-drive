import io
import json
import os
import random

import pytest

from tgdrive import crypto
from tgdrive.drive import TAG_CHUNK, TAG_INDEX, Drive, DriveError, parse_range
from tgdrive.fake import FakeTelegram
from tgdrive.store import Store

MB = 1024 * 1024
CHUNK = 9 * MB  # small chunks so tests cover several chunks and segments


async def make(tmp_path, accounts=2, name="t.db"):
    tg = FakeTelegram()
    store = Store(tmp_path / name)
    drive = Drive(store, tg, chunk_size=CHUNK, snapshot_delay=0)
    drive.unlock(b"k" * 32)
    for i in range(accounts):
        tg.add_user(f"+1555000000{i}", f"User {i}")
        res = await tg.start_login(f"+1555000000{i}")
        res = await tg.submit_code(res.login_id, "12345")
        aid = store.upsert_account(res.user.id, res.user.phone, res.user.name, f"acc{i}", res.session)
        await tg.attach(aid, res.session)
    return drive, tg, store


async def read_all(drive, path, rng=None):
    _, dl = await drive.read(path, rng)
    out = b"".join([c async for c in dl.chunks])
    return out, dl


def blob(n, seed=1):
    return random.Random(seed).randbytes(n)


async def test_roundtrip_multi_chunk_and_spread(tmp_path):
    drive, tg, store = await make(tmp_path)
    data = blob(25 * MB + 123)
    e = await drive.write("/video.mp4", io.BytesIO(data), len(data))
    assert e.size == len(data) and e.mime == "video/mp4"
    chunks = store.chunks(store.child("root", "video.mp4")["cid"])
    assert len(chunks) == 3
    assert {c["account_id"] for c in chunks} == {1, 2}  # spread over both accounts
    got, dl = await read_all(drive, "/video.mp4")
    assert got == data and dl.status == 200


async def test_telegram_only_sees_ciphertext(tmp_path):
    drive, tg, store = await make(tmp_path, accounts=1)
    secret = b"my bank statement " * 1000
    await drive.write("/Private/statement.pdf".replace("/Private", ""), io.BytesIO(secret), len(secret))
    stored = list(tg.accounts.values())[0].messages
    for m in stored.values():
        assert b"bank statement" not in m.data
        assert "statement" not in m.caption and m.caption.startswith(TAG_CHUNK)
        assert "statement" not in m.file_name


@pytest.mark.parametrize("rng", ["bytes=0-0", "bytes=0-99", f"bytes={4*MB-20}-{4*MB+20}",
                                 f"bytes={9*MB-5}-{9*MB+5}", f"bytes={20*MB}-", "bytes=-1000",
                                 f"bytes={8*MB}-{18*MB+7}"])
async def test_ranges_across_segment_and_chunk_boundaries(tmp_path, rng):
    drive, tg, store = await make(tmp_path)
    data = blob(25 * MB + 77, seed=2)
    await drive.write("/a.bin", io.BytesIO(data), len(data))
    start, end = parse_range(rng, len(data))
    got, dl = await read_all(drive, "/a.bin", rng)
    assert dl.status == 206 and got == data[start:end + 1]
    assert dl.content_range == f"bytes {start}-{end}/{len(data)}"


async def test_range_reads_only_needed_parts(tmp_path):
    drive, tg, store = await make(tmp_path, accounts=1)
    data = blob(25 * MB)
    await drive.write("/big", io.BytesIO(data), len(data))
    tg.calls.clear()
    await read_all(drive, "/big", "bytes=20000000-20000010")
    downloads = [c for c in tg.calls if c.startswith("download")]
    assert len(downloads) == 1
    length = int(downloads[0].split(":")[-1])
    assert length == 4 * MB  # one sealed segment, not the whole 9 MB chunk


async def test_unsatisfiable_range(tmp_path):
    drive, _, _ = await make(tmp_path)
    await drive.write("/s", io.BytesIO(b"abc"), 3)
    with pytest.raises(DriveError) as ei:
        await drive.read("/s", "bytes=10-20")
    assert ei.value.status == 416


async def test_empty_and_small_files(tmp_path):
    drive, tg, store = await make(tmp_path)
    await drive.write("/empty.txt", io.BytesIO(b""), 0)
    got, dl = await read_all(drive, "/empty.txt")
    assert got == b"" and dl.size == 0
    await drive.write("/one", io.BytesIO(b"x"), 1)
    assert (await read_all(drive, "/one"))[0] == b"x"


async def test_tamper_is_detected(tmp_path):
    drive, tg, store = await make(tmp_path, accounts=1)
    await drive.write("/f", io.BytesIO(b"hello" * 100), 500)
    msg = next(iter(list(tg.accounts.values())[0].messages.values()))
    msg.data = msg.data[:10] + bytes([msg.data[10] ^ 1]) + msg.data[11:]
    with pytest.raises(DriveError) as ei:
        await read_all(drive, "/f")
    assert "integrity" in str(ei.value)


async def test_tree_operations(tmp_path):
    drive, tg, store = await make(tmp_path)
    await drive.mkdir("/Docs")
    await drive.makedirs("/Docs/2026/Tax")
    await drive.write("/Docs/2026/Tax/form.pdf", io.BytesIO(b"pdf"), 3)
    assert [e.name for e in await drive.ls("/Docs")] == ["2026"]
    with pytest.raises(DriveError) as ei:
        await drive.mkdir("/Docs")
    assert ei.value.status == 405
    await drive.move("/Docs/2026", "/Archive-2026")
    assert (await read_all(drive, "/Archive-2026/Tax/form.pdf"))[0] == b"pdf"
    with pytest.raises(DriveError):
        await drive.move("/Archive-2026", "/Archive-2026/Tax/inside")
    with pytest.raises(DriveError):
        await drive.ls("/../x")


async def test_copy_shares_content_and_delete_garbage_collects(tmp_path):
    drive, tg, store = await make(tmp_path, accounts=1)
    data = blob(3 * MB)
    await drive.write("/a.bin", io.BytesIO(data), len(data))
    uploads = len([c for c in tg.calls if c.startswith("upload")])
    await drive.copy("/a.bin", "/b.bin")
    assert len([c for c in tg.calls if c.startswith("upload")]) == uploads  # no re-upload
    msgs = list(tg.accounts.values())[0].messages
    n = len(msgs)
    await drive.delete("/a.bin")
    assert len(msgs) == n  # still used by the copy
    assert (await read_all(drive, "/b.bin"))[0] == data
    await drive.delete("/b.bin")
    assert len(msgs) == n - 1  # content gone from Telegram


async def test_overwrite_replaces_content(tmp_path):
    drive, tg, store = await make(tmp_path, accounts=1)
    await drive.write("/n.txt", io.BytesIO(b"one"), 3)
    await drive.write("/n.txt", io.BytesIO(b"two!"), 4)
    assert (await read_all(drive, "/n.txt"))[0] == b"two!"
    assert len(list(tg.accounts.values())[0].messages) == 1
    with pytest.raises(DriveError):
        await drive.mkdir("/dir")
        await drive.write("/dir", io.BytesIO(b"x"), 1)


async def test_failed_upload_leaves_nothing_behind(tmp_path):
    drive, tg, store = await make(tmp_path, accounts=1)
    tg.fail_uploads = 99
    data = blob(20 * MB)
    with pytest.raises(DriveError):
        await drive.write("/x", io.BytesIO(data), len(data))
    assert not await drive.exists("/x")
    assert store.all_chunks() == []
    assert list(tg.accounts.values())[0].messages == {}


async def test_transient_upload_failure_is_retried(tmp_path):
    drive, tg, store = await make(tmp_path, accounts=1)
    tg.fail_uploads = 1
    await drive.write("/x", io.BytesIO(b"abc"), 3)
    assert (await read_all(drive, "/x"))[0] == b"abc"


async def test_no_accounts(tmp_path):
    drive, tg, store = await make(tmp_path, accounts=0)
    with pytest.raises(DriveError) as ei:
        await drive.write("/x", io.BytesIO(b"a"), 1)
    assert ei.value.status == 503


async def test_rebuild_on_new_server(tmp_path):
    drive, tg, store = await make(tmp_path)
    await drive.makedirs("/Photos/2026")
    data = blob(12 * MB)
    await drive.write("/Photos/2026/trip.jpg", io.BytesIO(data), len(data))
    await drive.write("/notes.txt", io.BytesIO(b"hi"), 2)
    await drive.copy("/notes.txt", "/Photos/notes-copy.txt")
    await drive.snapshot()
    # uploaded after the last snapshot: must come back through its captions
    await drive.write("/late.txt", io.BytesIO(b"late"), 4)

    # new server: empty database, same recovery key, same Telegram accounts
    store2 = Store(tmp_path / "new.db")
    drive2 = Drive(store2, tg, chunk_size=CHUNK)
    drive2.unlock(b"k" * 32)
    for acc in store.accounts():
        aid = store2.upsert_account(acc["tg_user_id"], acc["phone"], acc["name"], acc["label"], acc["session"])
        await tg.attach(aid, acc["session"])
    stats = await drive2.rebuild()
    assert stats["files"] == 3 and stats["recovered"] == 1
    assert (await read_all(drive2, "/Photos/2026/trip.jpg"))[0] == data
    assert (await read_all(drive2, "/Photos/notes-copy.txt"))[0] == b"hi"
    assert (await read_all(drive2, "/Recovered files/late.txt"))[0] == b"late"


async def test_rebuild_with_wrong_key_fails(tmp_path):
    drive, tg, store = await make(tmp_path)
    await drive.write("/a", io.BytesIO(b"a"), 1)
    await drive.snapshot()
    store2 = Store(tmp_path / "other.db")
    drive2 = Drive(store2, tg, chunk_size=CHUNK)
    drive2.unlock(b"z" * 32)
    for acc in store.accounts():
        aid = store2.upsert_account(acc["tg_user_id"], acc["phone"], acc["name"], acc["label"], acc["session"])
        await tg.attach(aid, acc["session"])
    with pytest.raises(DriveError) as ei:
        await drive2.rebuild()
    assert "recovery key" in str(ei.value)


async def test_rebuild_into_non_empty_drive_uses_new_folder(tmp_path):
    drive, tg, store = await make(tmp_path)
    await drive.write("/a.txt", io.BytesIO(b"a"), 1)
    await drive.snapshot()
    stats = await drive.rebuild()
    names = [e.name for e in await drive.ls("/")]
    assert "a.txt" in names and any(n.startswith("Restored ") for n in names)
    assert stats["files"] == 1


async def test_snapshots_keep_only_newest(tmp_path):
    drive, tg, store = await make(tmp_path, accounts=1)
    for i in range(5):
        await drive.write(f"/f{i}", io.BytesIO(b"x"), 1)
        await drive.snapshot()
    msgs = list(tg.accounts.values())[0].messages.values()
    assert len([m for m in msgs if m.caption.startswith(TAG_INDEX)]) == 3


async def test_evacuate_moves_parts(tmp_path):
    drive, tg, store = await make(tmp_path)
    data = blob(30 * MB)
    await drive.write("/big", io.BytesIO(data), len(data))
    moved = await drive.evacuate(1)
    assert moved > 0
    assert {c["account_id"] for c in store.all_chunks()} == {2}
    assert (await read_all(drive, "/big"))[0] == data


async def test_unreachable_account_deletes_are_queued(tmp_path):
    drive, tg, store = await make(tmp_path, accounts=1)
    await drive.write("/a", io.BytesIO(b"a"), 1)
    session = tg.attached.pop(1)
    await drive.delete("/a")
    assert store.pending_deletes() == {1: [1]}
    tg.attached[1] = session
    await drive.flush_deletes()
    assert store.pending_deletes() == {}


async def test_search(tmp_path):
    drive, _, _ = await make(tmp_path)
    await drive.makedirs("/Work/2026")
    await drive.write("/Work/2026/Invoice-May.pdf", io.BytesIO(b"x"), 1)
    res = await drive.search("invoice")
    assert [(r["name"], r["folder"]) for r in res] == [("Invoice-May.pdf", "/Work/2026")]


def test_crypto_segments_are_4mib_aligned():
    assert crypto.SEGMENT + crypto.TAG == 4 * MB
    assert crypto.stored_size(crypto.SEGMENT * 2) == 8 * MB


def test_recovery_key_format_roundtrip():
    key = crypto.new_master_key()
    text = crypto.format_recovery_key(key)
    assert crypto.parse_recovery_key(text.lower().replace("-", " ")) == key
    with pytest.raises(ValueError):
        crypto.parse_recovery_key("not-a-key")
