# vpnprobe

Repository: [https://github.com/yaroslaff/vpnprobe](https://github.com/yaroslaff/vpnprobe)

`vpnprobe` is an unprivileged Python 3.13 library for checking direct SS,
VLESS, and Hysteria2 VPN URLs, MTProto proxy URLs, and subscriptions. Its
`vpnprobe ping` CLI performs quick direct-VPN and MTProto checks.

It has no database integration and no SQLite, SQLAlchemy, Alembic, or Telegram
Bot API dependency. Library callers provide all settings explicitly.

## Installation

```bash
python3.13 -m venv .venv
.venv/bin/pip install 'git+https://github.com/yaroslaff/vpnprobe.git'
.venv/bin/vpnprobe check
```

Upgrade from the same Git repository:

```bash
.venv/bin/pip install --upgrade 'git+https://github.com/yaroslaff/vpnprobe.git'
```

## Usage

```bash
.venv/bin/vpnprobe ping 'vless://...'
.venv/bin/vpnprobe ping 'tg://proxy?...' --dc ALL
```

The process runs without root privileges. Runtime checks need outbound network
access and, depending on the protocol, executable `xray-knife`/`sing-box`, the
official `hysteria` client, and a loadable TDLib JSON library. Hysteria2 checks
use the native client with a disposable mode-0600 configuration and loopback
SOCKS5 listener. Temporary tunnel and TDLib state is removed after each check.

`vpnprobe check` checks all external runtime dependencies without contacting the
network. It reports the installed executable or library and its version when
available. For a missing dependency, it prints a short Debian 13 installation
instruction for the latest xray-knife, sing-box, Hysteria, or packaged TDLib.
