"""Command line: ``tgdrive serve``, ``tgdrive demo``, ``tgdrive set-password``."""
from __future__ import annotations

import argparse
import asyncio
import base64
import getpass
import io
import logging
import sys
import tempfile
from pathlib import Path

from . import __version__
from .config import Settings
from .security import Vault, hash_password
from .store import Store


def _serve(app, host: str, port: int) -> None:
    import uvicorn
    # Client addresses come from the socket; the app reads proxy headers itself only when
    # TGDRIVE_TRUST_PROXY=1, so nobody can fake their address to dodge rate limits.
    uvicorn.run(app, host=host, port=port, proxy_headers=False, log_level="info")


def cmd_serve(args: argparse.Namespace) -> None:
    from .app import create_app
    settings = Settings.from_env()
    if not settings.telegram_configured:
        print("Note: TELEGRAM_API_ID / TELEGRAM_API_HASH are not set, so you cannot link "
              "Telegram accounts yet. See README > Telegram setup.", file=sys.stderr)
    _serve(create_app(settings), args.host, args.port)


def cmd_demo(args: argparse.Namespace) -> None:
    from . import crypto
    from .app import create_app
    from .demo import populate
    from .fake import FakeTelegram
    tmp = Path(tempfile.mkdtemp(prefix="tgdrive-demo-"))
    settings = Settings(data_dir=tmp, base_url=f"http://localhost:{args.port}", telegram_api_id=1,
                        telegram_api_hash="demo", secret_key="demo-only-secret", demo=True,
                        chunk_mb=16)
    store = Store(tmp / "tgdrive.db")
    tg = FakeTelegram()
    asyncio.run(populate(store, tg, Vault(settings.secret_key), settings.chunk_mb))
    store.set("password_hash", hash_password("demo-password"))
    print("\n  Demo running with 2 sample Telegram accounts (in memory, nothing is saved).")
    print(f"  Open http://localhost:{args.port} and sign in with password: demo-password")
    print("  To link another demo account use phone +1 555 0100, code 12345.\n")
    _serve(create_app(settings, store, tg), args.host, args.port)


def cmd_set_password(args: argparse.Namespace) -> None:
    settings = Settings.from_env()
    store = Store(settings.data_dir / "tgdrive.db")
    pw = getpass.getpass("New password (10+ characters): ")
    if len(pw) < 10 or pw != getpass.getpass("Repeat: "):
        sys.exit("Passwords do not match or are too short.")
    store.set("password_hash", hash_password(pw))
    store.delete_all_sessions()
    if args.reset_2fa:
        store.set("totp_secret", None)
    print("Password updated. All sessions were signed out.")


def main(argv: list[str] | None = None) -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    logging.getLogger("telethon").setLevel(logging.WARNING)
    p = argparse.ArgumentParser(prog="tgdrive", description="Unlimited encrypted storage in Telegram.")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)
    for name, fn in (("serve", cmd_serve), ("demo", cmd_demo)):
        s = sub.add_parser(name)
        s.add_argument("--host", default="0.0.0.0" if name == "serve" else "127.0.0.1")
        s.add_argument("--port", type=int, default=8080)
        s.set_defaults(fn=fn)
    s = sub.add_parser("set-password", help="set or reset the login password")
    s.add_argument("--reset-2fa", action="store_true", help="also turn off two-factor login")
    s.set_defaults(fn=cmd_set_password)
    args = p.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
