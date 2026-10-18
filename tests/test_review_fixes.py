"""Regression tests for issues found in code review."""
import asyncio
import io

import pytest

from tgdrive import crypto
from tgdrive.drive import DriveError, parse_range
from tgdrive.telegram import TelegramError

from .test_drive import CHUNK, MB, blob, make, read_all


def messages(tg):
    return sum(len(a.messages) for a in tg.accounts.values())


async def test_move_onto_own_parent_is_refused_and_keeps_files(tmp_path):
    drive, tg, store = await make(tmp_path)
    await drive.mkdir("/a")
    await drive.write("/a/b", io.BytesIO(b"bee"), 3)
    await drive.write("/a/sibling", io.BytesIO(b"sib"), 3)
    with pytest.raises(DriveError) as e:
        await drive.move("/a/b", "/a", overwrite=True)
    assert e.value.status == 409
    with pytest.raises(DriveError):
        await drive.copy("/a/b", "/a", overwrite=True)
    assert (await read_all(drive, "/a/sibling"))[0] == b"sib"
    assert (await read_all(drive, "/a/b"))[0] == b"bee"


async def test_overwrite_during_download_lets_the_download_finish(tmp_path):
    drive, tg, store = await make(tmp_path, accounts=1)
    data = blob(2 * CHUNK)
    await drive.write("/v", io.BytesIO(data), len(data))
    _, dl = await drive.read("/v")
    it = dl.chunks.__aiter__()
    got = [await it.__anext__()]
    await drive.write("/v", io.BytesIO(b"new"), 3)  # old content is now unused
    got += [c async for c in it]
    assert b"".join(got) == data
    # the old parts are queued for deletion after a grace period, not leaked
    assert store._exec("SELECT COUNT(*) FROM delete_queue").fetchone()[0] == 2
    assert store.pending_deletes() == {}
    store._exec("UPDATE delete_queue SET not_before=0")
    await drive.flush_deletes()
    assert messages(tg) == 1


def test_recovery_key_has_checksum():
    key = crypto.format_recovery_key(b"k" * 32)
    assert len(key.split("-")) == 14
    assert crypto.parse_recovery_key(key.lower().replace("-", " ")) == b"k" * 32
    typo = ("B" if key[0] != "B" else "C") + key[1:]
    with pytest.raises(ValueError, match="typo"):
        crypto.parse_recovery_key(typo)
    with pytest.raises(ValueError):
        crypto.parse_recovery_key("A" * 52)


async def test_wrong_key_is_detected_against_telegram(tmp_path):
    drive, tg, store = await make(tmp_path)
    await drive.write("/f", io.BytesIO(b"x"), 1)
    assert await drive.check_key(b"k" * 32) is True
    assert await drive.check_key(b"z" * 32) is False


async def test_relinking_a_force_unlinked_account_repoints_its_parts(tmp_path):
    drive, tg, store = await make(tmp_path, accounts=1)
    data = blob(CHUNK + 5)
    await drive.write("/f", io.BytesIO(data), len(data))
    old = store.accounts()[0]
    assert store.delete_account(old["id"])
    with pytest.raises(DriveError) as e:
        await drive.read("/f")
    assert e.value.status == 503  # refused before any response starts
    res = await tg.start_login(old["phone"])
    res = await tg.submit_code(res.login_id, "12345")
    new_id = store.upsert_account(res.user.id, res.user.phone, res.user.name, "again", res.session)
    await tg.attach(new_id, res.session)
    assert new_id != old["id"]
    assert (await read_all(drive, "/f"))[0] == data


async def test_rebuild_repairs_parts_of_a_vanished_account(tmp_path):
    drive, tg, store = await make(tmp_path, accounts=1)
    await drive.write("/f", io.BytesIO(b"hello"), 5)
    store._exec("UPDATE chunks SET account_id=99")  # e.g. account row lost
    stats = await drive.rebuild()
    assert stats["repaired"] == 1 and stats["recovered"] == 0
    assert (await read_all(drive, "/f"))[0] == b"hello"


async def test_failed_upload_leaves_nothing_behind(tmp_path):
    drive, tg, store = await make(tmp_path, accounts=1)
    real = tg.upload

    async def flaky(account_id, data, size, file_name, caption):
        if ".00000." in file_name:
            await asyncio.sleep(0.05)
            raise TelegramError("bad request", 400)
        return await real(account_id, data, size, file_name, caption)

    tg.upload = flaky
    data = blob(4 * CHUNK)
    with pytest.raises(DriveError):
        await drive.write("/big", io.BytesIO(data), len(data))
    assert messages(tg) == 0 and store.all_chunks() == []


async def test_long_non_latin_names(tmp_path):
    drive, tg, store = await make(tmp_path, accounts=1)
    name = "文件" * 100 + "😀" * 50
    await drive.write("/" + name[:250], io.BytesIO(b"x"), 1)
    assert (await read_all(drive, "/" + name[:250]))[0] == b"x"


async def test_upload_racing_mkdir_is_a_clean_conflict(tmp_path):
    drive, tg, store = await make(tmp_path, accounts=1)
    real = tg.upload

    async def slow(*a, **kw):
        await drive.mkdir("/same")
        return await real(*a, **kw)

    tg.upload = slow
    with pytest.raises(DriveError) as e:
        await drive.write("/same", io.BytesIO(b"x"), 1)
    assert e.value.status == 409
    assert messages(tg) == 0


async def test_evacuate_racing_delete_does_not_resurrect(tmp_path):
    drive, tg, store = await make(tmp_path)
    await drive.write("/f", io.BytesIO(b"data"), 4)
    src = store.all_chunks()[0]["account_id"]
    real = tg.upload

    async def upload_then_delete(*a, **kw):
        mid = await real(*a, **kw)
        await drive.delete("/f")
        return mid

    tg.upload = upload_then_delete
    await drive.evacuate(src)
    assert store.all_chunks() == [] and messages(tg) == 0


def test_backwards_range_is_ignored():
    assert parse_range("bytes=5-2", 10) is None
    assert parse_range("bytes=2-5", 10) == (2, 5)


async def test_backslash_names_rejected(tmp_path):
    drive, tg, store = await make(tmp_path, accounts=1)
    with pytest.raises(DriveError):
        await drive.mkdir("/a\\b")
