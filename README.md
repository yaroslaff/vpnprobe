# vpnprobe

`vpnprobe` is an unprivileged Python 3.13 library for checking direct SS,
VLESS, and Hysteria2 VPN URLs, MTProto proxy URLs, and subscriptions. Its
`vpnprobe ping` CLI performs quick direct-VPN and MTProto checks.

It has no database integration and no SQLite, SQLAlchemy, Alembic, or Telegram
Bot API dependency. Library callers provide all settings explicitly.

```bash
python3.13 -m venv .venv
.venv/bin/pip install --editable '.[dev]'
.venv/bin/vpnprobe ping 'vless://...'
.venv/bin/vpnprobe ping 'tg://proxy?...' --dc ALL
make check
```

The process runs without root privileges. Runtime checks need outbound network
access and, depending on the protocol, executable `xray-knife`/`sing-box`, the
official `hysteria` client, and a loadable TDLib JSON library. Hysteria2 checks
use the native client with a disposable mode-0600 configuration and loopback
SOCKS5 listener. Temporary tunnel and TDLib state is removed after each check.
