# vpnprobe

Repository: [https://github.com/yaroslaff/vpnprobe](https://github.com/yaroslaff/vpnprobe)

`vpnprobe` is an unprivileged Python 3.13 library for checking direct SS,
VLESS, and Hysteria2 VPN URLs, MTProto proxy URLs, and subscriptions. Its
`vpnprobe ping` CLI performs quick direct-VPN and MTProto checks.

It has no database integration and no SQLite, SQLAlchemy, Alembic, or Telegram
Bot API dependency. Library callers provide all settings explicitly.

## Installation

```bash
pipx install git+https://github.com/yaroslaff/vpnprobe.git
vpnprobe check
```

Upgrade from the same Git repository:


## Usage

```bash
vpnprobe ping 'vless://...'
vpnprobe ping 'tg://proxy?...' --dc ALL
vpnprobe subscription 'https://example.com/subscription'
# Short alias:
vpnprobe sub 'https://example.com/subscription'
```

`vpnprobe subscription` downloads a subscription, decodes whole-list Base64
when necessary, and prints one SS, VLESS, or Hysteria2 URL per line. It does
not test the returned VPN URLs. The equivalent library function is the async
`fetch_subscription(url, settings)`, which returns the URLs without printing.

The process runs without root privileges. Runtime checks need outbound network
access and, depending on the protocol, executable `xray-knife`/`sing-box`, the
official `hysteria` client, and a loadable TDLib JSON library. Hysteria2 checks
use the native client with a disposable mode-0600 configuration and loopback
SOCKS5 listener. Temporary tunnel and TDLib state is removed after each check.

`vpnprobe check` checks all external runtime dependencies without contacting the
network. It reports the installed executable or library and its version when
available. For a missing dependency, it prints a short Debian 13 installation
instruction for the latest xray-knife, sing-box, Hysteria, or packaged TDLib.

## Exit codes

`vpnprobe ping` first prints the decoded configuration, exactly as
`xray-knife parse` reports it, and then the probe verdict. Missing or
unusable `xray-knife` only removes those details; it never changes the
status.

`vpnprobe ping` returns `0` only when a request really succeeded through the
tunnel: the probe opens a disposable loopback SOCKS5 tunnel for the URL
(`xray-knife` for SS/VLESS/VMess/Trojan, the native client for Hysteria2) and
requires HTTP 204 from the connectivity endpoint. A failed check returns `1`,
and a bad URL or unusable dependency returns `2`. The exit codes of
`xray-knife` and `hysteria` are not trusted, because both exit `0` even when
their own checks fail.
