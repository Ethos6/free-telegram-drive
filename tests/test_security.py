import pytest

from tgdrive.security import Throttle, Vault, hash_password, totp, verify_password, verify_totp

RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # b"12345678901234567890"


def test_totp_matches_rfc6238_vectors():
    # RFC 6238 appendix B (SHA-1), last 6 of the 8 digits
    assert totp(RFC_SECRET, at=59) == "287082"
    assert totp(RFC_SECRET, at=1111111109) == "081804"
    assert totp(RFC_SECRET, at=2000000000) == "279037"


def test_totp_window():
    code = totp(RFC_SECRET, at=1000)
    assert verify_totp(RFC_SECRET, code, at=1000 + 30)
    assert not verify_totp(RFC_SECRET, code, at=1000 + 95)
    assert not verify_totp(RFC_SECRET, "abc", at=1000)


def test_password_hash():
    h = hash_password("s3cret pass")
    assert h.startswith("scrypt$") and verify_password("s3cret pass", h)
    assert not verify_password("wrong", h)
    assert not verify_password("x", "garbage")


def test_vault_roundtrip_and_wrong_key():
    token = Vault("k1").seal("refresh-token")
    assert "refresh-token" not in token
    assert Vault("k1").open(token) == "refresh-token"
    with pytest.raises(ValueError):
        Vault("k2").open(token)


def test_throttle():
    t = Throttle(limit=2, window=60)
    t.fail("ip")
    assert not t.blocked("ip")
    t.fail("ip")
    assert t.blocked("ip")
    t.reset("ip")
    assert not t.blocked("ip")
