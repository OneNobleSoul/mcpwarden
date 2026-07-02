from __future__ import annotations

import argparse
from pathlib import Path

from . import __version__
from .config import ServerSpec, discover
from .detectors import scan_servers, scan_tools
from .findings import Finding, Severity
from .lockfile import Lockfile, build, diff
from .mcpclient import MCPError, list_tools
from .report import exit_code, render, render_json

DEFAULT_LOCK = Path("mcpwarden.lock")


def _fail_on(value: str) -> Severity | None:
    if value == "never":
        return None
    return Severity.parse(value)


def _emit(findings: list[Finding], args: argparse.Namespace) -> int:
    if getattr(args, "json", False):
        render_json(findings)
    else:
        render(findings)
    return exit_code(findings, _fail_on(args.fail_on))


def _resolve_servers(args: argparse.Namespace) -> list[ServerSpec]:
    paths = [Path(p) for p in args.config] if args.config else None
    servers = discover(paths)
    wanted = getattr(args, "server", None)
    if wanted:
        servers = [s for s in servers if s.name in set(wanted)]
    return servers


def _collect_live_tools(
    servers: list[ServerSpec], timeout: float
) -> tuple[dict[str, list[dict]], list[Finding]]:
    """Launch each local server and grab its tools, turning failures into findings."""
    tools: dict[str, list[dict]] = {}
    problems: list[Finding] = []
    for spec in servers:
        if spec.is_remote:
            problems.append(
                Finding(
                    rule="conn.remote-skipped",
                    severity=Severity.INFO,
                    title=f"Skipped remote server {spec.name}",
                    detail="remote (http/sse) servers aren't inspected yet.",
                    server=spec.name,
                )
            )
            continue
        try:
            tools[spec.name] = list_tools(spec, timeout=timeout)
        except MCPError as exc:
            problems.append(
                Finding(
                    rule="conn.failed",
                    severity=Severity.LOW,
                    title=f"Could not talk to {spec.name}",
                    detail=str(exc),
                    server=spec.name,
                )
            )
    return tools, problems


def _cmd_scan(args: argparse.Namespace) -> int:
    servers = _resolve_servers(args)
    findings = scan_servers(servers)
    return _emit(findings, args)


def _cmd_inspect(args: argparse.Namespace) -> int:
    servers = _resolve_servers(args)
    tools, problems = _collect_live_tools(servers, args.timeout)
    findings = list(problems)
    findings += scan_servers(servers)
    for name, tool_defs in tools.items():
        findings += scan_tools(name, tool_defs)
    return _emit(findings, args)


def _cmd_pin(args: argparse.Namespace) -> int:
    servers = _resolve_servers(args)
    tools, problems = _collect_live_tools(servers, args.timeout)
    if problems:
        render(problems)
    lock = build(tools)
    lock.save(args.lock)
    total = sum(len(t) for t in tools.values())
    print(f"pinned {total} tool(s) across {len(tools)} server(s) -> {args.lock}")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    if not Path(args.lock).is_file():
        print(f"no lockfile at {args.lock}; run `mcpwarden pin` first")
        return 2
    pinned = Lockfile.load(args.lock)
    servers = _resolve_servers(args)
    tools, problems = _collect_live_tools(servers, args.timeout)
    live = build(tools)
    findings = list(problems)
    findings += diff(pinned, live)
    # while we're connected anyway, re-run the poison heuristics
    for name, tool_defs in tools.items():
        findings += scan_tools(name, tool_defs)
    return _emit(findings, args)


def _add_common(sub: argparse.ArgumentParser) -> None:
    sub.add_argument(
        "-c", "--config", action="append",
        help="path to a client config (repeatable). Default: auto-discover.",
    )
    sub.add_argument(
        "-s", "--server", action="append",
        help="only act on this server name (repeatable).",
    )


def _add_output(sub: argparse.ArgumentParser) -> None:
    sub.add_argument("--json", action="store_true", help="emit findings as JSON")
    sub.add_argument(
        "--fail-on", default="medium",
        choices=["info", "low", "medium", "high", "critical", "never"],
        help="exit non-zero when a finding at or above this level shows up (default: medium)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcpwarden",
        description="Audit the MCP servers wired into your local clients.",
    )
    parser.add_argument("-V", "--version", action="version", version=f"mcpwarden {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="static audit of the discovered configs")
    _add_common(scan)
    _add_output(scan)
    scan.set_defaults(func=_cmd_scan)

    inspect = sub.add_parser("inspect", help="connect to servers and audit their live tools")
    _add_common(inspect)
    _add_output(inspect)
    inspect.add_argument("--timeout", type=float, default=20.0)
    inspect.set_defaults(func=_cmd_inspect)

    pin = sub.add_parser("pin", help="record the current tool definitions to a lockfile")
    _add_common(pin)
    pin.add_argument("--timeout", type=float, default=20.0)
    pin.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    pin.set_defaults(func=_cmd_pin)

    verify = sub.add_parser("verify", help="check live tools against the lockfile (rug-pulls)")
    _add_common(verify)
    _add_output(verify)
    verify.add_argument("--timeout", type=float, default=20.0)
    verify.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    verify.set_defaults(func=_cmd_verify)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)
