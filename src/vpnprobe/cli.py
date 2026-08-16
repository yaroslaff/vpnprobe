"""vpnprobe command-line interface."""

from __future__ import annotations

import argparse
import asyncio
import sys

from vpnprobe import __version__
from vpnprobe.errors import ProbeError
from vpnprobe.ping import PingOptions, ping


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vpnprobe")
    parser.add_argument("--version", action="version", version=f"vpnprobe {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    ping_parser = commands.add_parser("ping", help="test one VPN or MTProto proxy URL")
    ping_parser.add_argument("url")
    ping_parser.add_argument("--timeout", type=float, metavar="SECONDS")
    ping_parser.add_argument("-s", "--speedtest", action="store_true")
    ping_parser.add_argument("--dc", metavar="1|2|3|4|5|ALL")
    ping_parser.add_argument("--xray-knife", default="xray-knife", metavar="PATH")
    ping_parser.add_argument("--hysteria", default="hysteria", metavar="PATH")
    ping_parser.add_argument("--tdjson-library", default="", metavar="PATH")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    try:
        code = asyncio.run(
            ping(
                args.url,
                PingOptions(
                    timeout=args.timeout,
                    speedtest=args.speedtest,
                    dc=args.dc,
                    xray_knife_path=args.xray_knife,
                    hysteria_path=args.hysteria,
                    tdjson_library=args.tdjson_library,
                ),
            )
        )
    except (ProbeError, OSError) as exc:
        print(f"ERROR_COMMAND {str(exc).strip() or type(exc).__name__}", file=sys.stderr)
        raise SystemExit(2) from None
    raise SystemExit(code)
