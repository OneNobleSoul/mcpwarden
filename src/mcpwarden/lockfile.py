"""Pin tool definitions and diff them across scans.

The whole point: an MCP server can hand you a friendly `tools/list` today and a
poisoned one next week -- new hidden instruction in a description, a changed
input schema -- and nothing on the client side flags it. So we hash the full
tool definition (not just the description) and keep it in a lockfile. `verify`
re-reads the live tools and yells when a pinned hash no longer matches.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from .findings import Finding, Severity

LOCK_VERSION = 1


def canonical(tool: dict) -> str:
    """Stable JSON for a single tool definition.

    We deliberately keep every field except the display-only `title`, so a
    changed description or input schema moves the hash.
    """
    filtered = {k: v for k, v in tool.items() if k != "title"}
    return json.dumps(filtered, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def hash_tool(tool: dict) -> str:
    return hashlib.sha256(canonical(tool).encode("utf-8")).hexdigest()


@dataclass
class Lockfile:
    version: int = LOCK_VERSION
    # server -> { tool_name -> sha256 }
    servers: dict[str, dict[str, str]] = field(default_factory=dict)

    def to_json(self) -> str:
        body = {
            "version": self.version,
            "servers": {
                name: dict(sorted(tools.items()))
                for name, tools in sorted(self.servers.items())
            },
        }
        return json.dumps(body, indent=2, ensure_ascii=False) + "\n"

    @classmethod
    def from_json(cls, text: str) -> Lockfile:
        data = json.loads(text)
        version = int(data.get("version", LOCK_VERSION))
        if version != LOCK_VERSION:
            raise ValueError(f"unsupported lockfile version {version}")
        servers = {
            str(name): {str(t): str(h) for t, h in (tools or {}).items()}
            for name, tools in (data.get("servers") or {}).items()
        }
        return cls(version=version, servers=servers)

    def save(self, path: Path) -> None:
        Path(path).write_text(self.to_json(), encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> Lockfile:
        return cls.from_json(Path(path).read_text(encoding="utf-8"))


def build(servers_tools: dict[str, list[dict]]) -> Lockfile:
    servers: dict[str, dict[str, str]] = {}
    for server, tools in servers_tools.items():
        entry: dict[str, str] = {}
        for tool in tools:
            name = tool.get("name")
            if not name:
                continue
            entry[str(name)] = hash_tool(tool)
        servers[server] = entry
    return Lockfile(servers=servers)


def diff(old: Lockfile, new: Lockfile) -> list[Finding]:
    """Compare a pinned lockfile against a freshly built one."""
    findings: list[Finding] = []

    for server, new_tools in new.servers.items():
        old_tools = old.servers.get(server)
        if old_tools is None:
            findings.append(
                Finding(
                    rule="lock.server-added",
                    severity=Severity.LOW,
                    title=f"New server not in lockfile: {server}",
                    detail=f"{server} wasn't pinned. Re-run `pin` if you trust it.",
                    server=server,
                )
            )
            continue

        for tool, new_hash in new_tools.items():
            old_hash = old_tools.get(tool)
            if old_hash is None:
                findings.append(
                    Finding(
                        rule="lock.tool-added",
                        severity=Severity.MEDIUM,
                        title=f"New tool appeared: {server}.{tool}",
                        detail=(
                            f"{server} now exposes `{tool}`, which wasn't in the lock. "
                            f"A server adding tools after approval is worth a look."
                        ),
                        server=server,
                        location=tool,
                    )
                )
            elif old_hash != new_hash:
                findings.append(
                    Finding(
                        rule="lock.tool-redefined",
                        severity=Severity.HIGH,
                        title=f"Tool definition changed: {server}.{tool}",
                        detail=(
                            f"`{tool}` no longer matches the pinned hash "
                            f"({old_hash[:12]}.. -> {new_hash[:12]}..). This is the "
                            f"classic rug-pull shape: approve once, mutate later."
                        ),
                        server=server,
                        location=tool,
                    )
                )

        for tool in old_tools.keys() - new_tools.keys():
            findings.append(
                Finding(
                    rule="lock.tool-removed",
                    severity=Severity.INFO,
                    title=f"Pinned tool is gone: {server}.{tool}",
                    detail=f"{server} no longer exposes `{tool}`.",
                    server=server,
                    location=tool,
                )
            )

    for server in old.servers.keys() - new.servers.keys():
        findings.append(
            Finding(
                rule="lock.server-removed",
                severity=Severity.INFO,
                title=f"Pinned server is gone: {server}",
                detail=f"{server} was in the lock but isn't configured anymore.",
                server=server,
            )
        )

    return findings
