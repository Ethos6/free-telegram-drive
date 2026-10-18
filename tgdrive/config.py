"""Settings, read from environment variables (or a .env file in the working folder)."""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from pathlib import Path


def _load_dotenv(path: Path) -> None:
    if not path.is_file():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


@dataclass
class Settings:
    data_dir: Path
    base_url: str
    telegram_api_id: int
    telegram_api_hash: str
    secret_key: str
    demo: bool = False
    session_days: int = 30
    trust_proxy: bool = False
    chunk_mb: int = 256
    parallel: int = 3

    @property
    def secure_cookies(self) -> bool:
        return self.base_url.startswith("https://")

    @property
    def telegram_configured(self) -> bool:
        return bool(self.telegram_api_id and self.telegram_api_hash)

    @classmethod
    def from_env(cls) -> "Settings":
        _load_dotenv(Path.cwd() / ".env")
        data_dir = Path(os.environ.get("TGDRIVE_DATA", "./data")).resolve()
        data_dir.mkdir(parents=True, exist_ok=True)
        secret = os.environ.get("TGDRIVE_SECRET_KEY", "")
        if not secret:
            key_file = data_dir / "secret.key"
            if not key_file.exists():
                key_file.write_text(secrets.token_urlsafe(48))
                key_file.chmod(0o600)
            secret = key_file.read_text().strip()
        chunk_mb = int(os.environ.get("TGDRIVE_CHUNK_MB", "256"))
        if not 16 <= chunk_mb <= 1900:
            raise SystemExit("TGDRIVE_CHUNK_MB must be between 16 and 1900")
        return cls(
            data_dir=data_dir,
            base_url=os.environ.get("TGDRIVE_BASE_URL", "http://localhost:8080").rstrip("/"),
            telegram_api_id=int(os.environ.get("TELEGRAM_API_ID", "0") or 0),
            telegram_api_hash=os.environ.get("TELEGRAM_API_HASH", ""),
            secret_key=secret,
            demo=os.environ.get("TGDRIVE_DEMO", "") == "1",
            trust_proxy=os.environ.get("TGDRIVE_TRUST_PROXY", "") == "1",
            chunk_mb=chunk_mb,
            parallel=max(1, min(8, int(os.environ.get("TGDRIVE_PARALLEL", "3")))),
        )
