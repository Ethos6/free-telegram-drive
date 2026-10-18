# Security policy

## Reporting a vulnerability

Please report security problems privately through
[GitHub private vulnerability reporting](https://github.com/Ethos6/free-telegram-drive/security/advisories/new),
not in public issues. Include steps to reproduce and the version you tested. We aim to reply
within a few days and will credit you in the fix unless you prefer otherwise.

## Supported versions

Only the latest release on `main` receives security fixes.

## Security model, in short

- Files, names and the index are encrypted on the server before upload (AES-256-GCM with per-file
  keys derived by HKDF). Telegram stores ciphertext only.
- The master key and Telegram sessions are encrypted at rest with a key in `data/secret.key`
  (or `TGDRIVE_SECRET_KEY`). Anyone who can read both the database and that key can read your
  files, so protect the server and its backups. Setting `TGDRIVE_SECRET_KEY` from a secret store
  keeps the key out of the data folder.
- Whoever controls the server can read everything. Self-host on a machine you trust.
- Index backups are authenticated but carry no version counter: someone with access to your
  Saved Messages could delete newer backups so that *Rebuild* restores an older index. File
  contents cannot be changed without detection.
- Web sign-in uses a scrypt-hashed password, optional TOTP, throttling, and `SameSite=Lax`
  cookies plus a required custom header against CSRF. WebDAV accepts app passwords only.
