"""Client-side encryption of file chunks (AES-256-GCM in 4 MiB segments).

Telegram only ever receives ciphertext. Each chunk is split into fixed-size
segments that are sealed independently, so a byte range can be read and verified
without downloading the whole chunk (video seeking, resumed downloads).

Layout of an encrypted chunk: segment_0 || tag_0 || segment_1 || tag_1 || ...
Every segment except the last holds exactly SEGMENT plaintext bytes.

Keys: one 32-byte master key per vault (the "recovery key"). Each file gets its
own key, derived with HKDF from the master key and the file's random id. The
nonce is the chunk's random 8-byte prefix followed by the 4-byte segment index,
and the file id, chunk index and segment index are bound as associated data, so
segments cannot be swapped or replayed elsewhere.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct
from typing import BinaryIO, Iterator

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SEGMENT = 4 * 1024 * 1024 - 16  # so each sealed segment is exactly 4 MiB
TAG = 16


class DecryptError(Exception):
    pass


def new_master_key() -> bytes:
    return os.urandom(32)


def _key_check(key: bytes) -> bytes:
    return hashlib.sha256(b"tgdrive-recovery-key-v1" + key).digest()[:3]


def format_recovery_key(key: bytes) -> str:
    """Human-friendly form: 14 groups of 4 base32 characters (the key plus a 3-byte
    checksum, so a typo is caught instead of silently becoming a different key)."""
    s = base64.b32encode(key + _key_check(key)).decode()
    return "-".join(s[i:i + 4] for i in range(0, len(s), 4))


def parse_recovery_key(text: str) -> bytes:
    s = "".join(ch for ch in text.upper() if ch.isalnum())
    s = s.replace("0", "O").replace("1", "I").replace("8", "B")  # common misreadings
    if len(s) != 56:
        raise ValueError("a recovery key has 56 letters and digits (14 groups of 4)")
    try:
        raw = base64.b32decode(s)
    except Exception as e:
        raise ValueError("not a valid recovery key") from e
    key, check = raw[:32], raw[32:]
    if not hmac.compare_digest(check, _key_check(key)):
        raise ValueError("this recovery key has a typo; check it again")
    return key


def file_key(master: bytes, file_id: str) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"tgdrive-file-key-v1",
                info=file_id.encode()).derive(master)


def stored_size(plain_size: int) -> int:
    """Ciphertext size of a chunk with ``plain_size`` bytes of plaintext."""
    segments = max(1, -(-plain_size // SEGMENT))
    return plain_size + segments * TAG


def _nonce(prefix: bytes, seg: int) -> bytes:
    return prefix + struct.pack(">I", seg)


def _aad(file_id: str, chunk: int, seg: int, last: bool) -> bytes:
    return f"{file_id}|{chunk}|{seg}|{int(last)}".encode()


def encrypt_chunk(key: bytes, file_id: str, chunk: int, prefix: bytes, src: BinaryIO,
                  length: int, dst: BinaryIO) -> int:
    """Read ``length`` plaintext bytes from ``src``, write ciphertext to ``dst``."""
    aes = AESGCM(key)
    nseg = max(1, -(-length // SEGMENT))
    written = 0
    for seg in range(nseg):
        n = min(SEGMENT, length - seg * SEGMENT)
        data = src.read(n)
        if len(data) != n:
            raise IOError("source ended early")
        out = aes.encrypt(_nonce(prefix, seg), data, _aad(file_id, chunk, seg, seg == nseg - 1))
        dst.write(out)
        written += len(out)
    return written


def plain_to_stored(start: int, end: int, plain_size: int) -> tuple[int, int, int]:
    """For plaintext bytes [start, end] of a chunk return (first_segment,
    stored_offset, stored_length) covering whole segments."""
    first, last = start // SEGMENT, end // SEGMENT
    nseg = max(1, -(-plain_size // SEGMENT))
    last = min(last, nseg - 1)
    off = first * (SEGMENT + TAG)
    stop = min((last + 1) * (SEGMENT + TAG), stored_size(plain_size))
    return first, off, stop - off


def decrypt_segments(key: bytes, file_id: str, chunk: int, prefix: bytes, plain_size: int,
                     first_seg: int, data: bytes) -> Iterator[bytes]:
    """Decrypt consecutive whole segments starting at ``first_seg``."""
    aes = AESGCM(key)
    nseg = max(1, -(-plain_size // SEGMENT))
    pos, seg = 0, first_seg
    while pos < len(data):
        n = min(SEGMENT, plain_size - seg * SEGMENT) + TAG
        block = data[pos:pos + n]
        if len(block) != n:
            raise DecryptError("truncated segment")
        try:
            yield aes.decrypt(_nonce(prefix, seg), block, _aad(file_id, chunk, seg, seg == nseg - 1))
        except Exception as e:
            raise DecryptError(f"chunk {chunk} segment {seg} failed authentication") from e
        pos += n
        seg += 1


def seal_blob(master: bytes, label: str, data: bytes) -> bytes:
    """Encrypt a small blob (metadata backups) with a key bound to ``label``."""
    key = file_key(master, "blob:" + label)
    nonce = os.urandom(12)
    return b"TGD1" + nonce + AESGCM(key).encrypt(nonce, data, label.encode())


def open_blob(master: bytes, label: str, blob: bytes) -> bytes:
    if blob[:4] != b"TGD1":
        raise DecryptError("not a Telegram Drive backup")
    key = file_key(master, "blob:" + label)
    try:
        return AESGCM(key).decrypt(blob[4:16], blob[16:], label.encode())
    except Exception as e:
        raise DecryptError("wrong recovery key or damaged backup") from e
