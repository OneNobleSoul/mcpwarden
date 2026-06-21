from __future__ import annotations

import argparse
from pathlib import Path

from . import __version__
from .config import discover
from .detectors import scan_servers
from .report import render


def _cmd_scan(args: argparse.Namespace) -> int:
    paths = [Path(p) for p in args.config] if args.config else None
    servers = discover(paths)
    findings = scan_servers(servers)
    render(findings)
    return 1 if findings else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcpwarden",
        description="Audit the MCP servers wired into your local clients.",
    )
    parser.add_argument("-V", "--version", action="version", version=f"mcpwarden {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="static audit of the discovered configs")
    scan.add_argument(
        "-c", "--config", action="append",
        help="path to a client config (repeatable). Default: auto-discover.",
    )
    scan.set_defaults(func=_cmd_scan)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)
