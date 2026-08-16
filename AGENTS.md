# Repository instructions

## Scope and architecture

- Build `vpnprobe`, an unprivileged Python 3.13 library for checking SS, VLESS,
  Hysteria2, MTProto proxy, and VPN subscription URLs, plus a `ping` CLI for
  direct VPN and MTProto proxy URLs.
- Keep `vpnprobe` independent of vpnshare persistence and product logic. Do not add SQLite, SQLAlchemy, Alembic, Telegram Bot API, user, distribution, or scheduling dependencies.
- Expose one typed asyncio-native Python API and make the CLI a thin adapter over that API.
- Do not read vpnshare configuration or databases. Accept inputs and options explicitly and write only disposable runtime data to temporary directories.

## Platform and quality

- Target Debian 13 and Python 3.13 exclusively.
- Use modern typed Python, mypy strict mode, Ruff, pytest with pytest-asyncio, and at least 90% test coverage.
- Pin dependencies exactly and package with Hatchling.
- Ordinary tests must not require external network access, real VPN keys, TDLib, xray-knife, or sing-box.
- Keep code, identifiers, CLI output, logs, diagnostics, and developer documentation in English.
- Do not add server-side CI; checks run locally.

## Security and runtime

- Never require root, privileged containers, elevated Linux capabilities, or access to the vpnshare database.
- Treat VPN URLs, proxy credentials, and subscription URLs as secrets. Do not persist them or expose them in unexpected diagnostics.
- Clean up all temporary files, TDLib state, tunnel processes, and process groups after success, failure, timeout, or interruption.
