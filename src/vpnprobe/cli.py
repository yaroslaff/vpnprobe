"""vpnprobe command-line interface."""

from __future__ import annotations

import argparse
import asyncio
import sys

from vpnprobe import __version__
from vpnprobe.config import Settings
from vpnprobe.diagnostics import check_dependencies, print_dependency_check
from vpnprobe.errors import ProbeError
from vpnprobe.installer import run_setup
from vpnprobe.ping import PingOptions, ping
from vpnprobe.subscription import fetch_subscription


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
    subscription_parser = commands.add_parser(
        "subscription",
        aliases=["sub"],
        help="download and print VPN URLs from a subscription",
    )
    subscription_parser.add_argument("url")
    check_parser = commands.add_parser("check", help="check external runtime dependencies")
    check_parser.add_argument("--xray-knife", default="xray-knife", metavar="PATH")
    check_parser.add_argument("--hysteria", default="hysteria", metavar="PATH")
    check_parser.add_argument("--tdjson-library", default="", metavar="PATH")
    setup_parser = commands.add_parser(
        "setup", help="check and offer to install missing external runtime dependencies"
    )
    setup_parser.add_argument(
        "-y", "--yes", action="store_true", help="answer yes to every installation question"
    )
    setup_parser.add_argument(
        "--pin",
        action="store_true",
        help="install the tested pinned versions instead of the latest releases",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    try:
        if args.command == "check":
            code = print_dependency_check(
                check_dependencies(
                    xray_knife_path=args.xray_knife,
                    hysteria_path=args.hysteria,
                    tdjson_library=args.tdjson_library,
                )
            )
            raise SystemExit(code)
        if args.command == "setup":
            raise SystemExit(run_setup(yes=args.yes, pin=args.pin))
        if args.command in {"subscription", "sub"}:
            configs = asyncio.run(fetch_subscription(args.url, Settings()))
            print("\n".join(configs))
            raise SystemExit(0)
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
