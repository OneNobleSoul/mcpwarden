"""Pin tool definitions and diff them across scans.

The whole point: an MCP server can hand you a friendly `tools/list` today and a
poisoned one next week -- new hidden instruction in a description, a changed
input schema -- and nothing on the client side flags it. So we hash the full
tool definition (not just the description) and keep it in a lockfile. `verify`
re-reads the live tools and yells when a pinned hash no longer matches.
"""

from __future__ import annotations

import difflib
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from .detectors import CAPABILITY_HINT
from .findings import Finding, Severity

LOCK_VERSION = 2


def canonical(tool: dict) -> str:
    """Stable JSON for a single tool definition.

    We deliberately keep every field except the display-only `title`, so a
    changed description or input schema moves the hash.
    """
    filtered = {k: v for k, v in tool.items() if k != "title"}
    return json.dumps(filtered, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def hash_tool(tool: dict) -> str:
    return hashlib.sha256(canonical(tool).encode("utf-8")).hexdigest()


def _scope_snapshot(tool: dict) -> dict:
    """Reduced view of a tool definition, just the fields scope-creep cares about.

    Deliberately not the full tool dict -- that's what the hash is for. This is
    small and diff-friendly, meant to sit next to the hash in the lockfile.
    """
    schema = tool.get("inputSchema") or tool.get("input_schema") or {}
    properties = schema.get("properties") or {}
    return {
        "description": str(tool.get("description", "")),
        "required": sorted(schema.get("required") or []),
        "properties": sorted(properties.keys()),
        "additionalProperties": schema.get("additionalProperties", True),
        "enums": {
            k: sorted(v["enum"])
            for k, v in properties.items()
            if isinstance(v, dict) and isinstance(v.get("enum"), list)
        },
        "annotations": dict(tool.get("annotations") or {}),
    }


def _inserted_text(old: str, new: str) -> str:
    """The parts of `new` that weren't in `old` -- what actually got added."""
    sm = difflib.SequenceMatcher(None, old, new)
    changed = ("insert", "replace")
    return "".join(new[j1:j2] for tag, _, _, j1, j2 in sm.get_opcodes() if tag in changed)


def _classify_scope_change(old: dict, new: dict) -> tuple[Severity, list[str]] | None:
    """Look at *what* changed between two schema snapshots, not just *that* it did.

    Single weak/medium signals stay quiet -- typo fixes and harmless rewording
    shouldn't page anyone. Severity only climbs when independent signals line
    up, same principle as the shadow-tool detector: one clue is a data point,
    two or more are a pattern.
    """
    signals: list[str] = []
    strong = medium = weak = 0

    added_required = set(new["required"]) - set(old["required"])
    if added_required:
        signals.append(f"new required parameter(s): {', '.join(sorted(added_required))}")
        strong += 1

    if old["additionalProperties"] is False and new["additionalProperties"] is not False:
        signals.append("additionalProperties widened from false")
        strong += 1

    narrowed_enums_lost = {
        k for k in old["enums"] if k not in new["enums"] and k in new["properties"]
    }
    if narrowed_enums_lost:
        signals.append(f"enum constraint removed on: {', '.join(sorted(narrowed_enums_lost))}")
        medium += 1

    added_props = set(new["properties"]) - set(old["properties"])
    capability_props = {p for p in added_props if CAPABILITY_HINT.search(p)}
    if capability_props:
        signals.append(f"new capability-named parameter(s): {', '.join(sorted(capability_props))}")
        strong += 1

    old_ann, new_ann = old["annotations"], new["annotations"]
    if old_ann.get("readOnlyHint") is True and new_ann.get("readOnlyHint") is not True:
        signals.append("readOnlyHint downgraded")
        strong += 1
    if old_ann.get("destructiveHint") in (False, None) and new_ann.get("destructiveHint") is True:
        signals.append("destructiveHint newly set")
        strong += 1
    if old_ann.get("openWorldHint") is False and new_ann.get("openWorldHint") is not False:
        signals.append("openWorldHint newly set")
        medium += 1

    delta_text = _inserted_text(old["description"], new["description"])
    if CAPABILITY_HINT.search(delta_text):
        signals.append("capability wording added to description")
        weak += 1

    if strong == 0 and medium == 0 and weak == 0:
        return None
    if strong >= 2 and (medium + weak) >= 1:
        return Severity.CRITICAL, signals
    if strong >= 2 or (strong == 1 and (medium + weak) >= 1):
        return Severity.HIGH, signals
    if strong == 1:
        return Severity.MEDIUM, signals
    return Severity.LOW, signals


@dataclass
class ToolRecord:
    hash: str
    # None for tools pinned by a v1 lockfile, or anything else without a
    # snapshot on hand -- scope-creep classification is skipped in that case.
    schema: dict | None = None


@dataclass
class Lockfile:
    version: int = LOCK_VERSION
    # server -> { tool_name -> ToolRecord }
    servers: dict[str, dict[str, ToolRecord]] = field(default_factory=dict)

    def to_json(self) -> str:
        body = {
            "version": self.version,
            "servers": {
                name: {
                    tool: {"hash": rec.hash, "schema": rec.schema}
                    for tool, rec in sorted(tools.items())
                }
                for name, tools in sorted(self.servers.items())
            },
        }
        return json.dumps(body, indent=2, ensure_ascii=False) + "\n"

    @classmethod
    def from_json(cls, text: str) -> Lockfile:
        data = json.loads(text)
        version = int(data.get("version", LOCK_VERSION))
        if version not in (1, 2):
            raise ValueError(f"unsupported lockfile version {version}")
        servers: dict[str, dict[str, ToolRecord]] = {}
        for name, tools in (data.get("servers") or {}).items():
            entry: dict[str, ToolRecord] = {}
            for tool, value in (tools or {}).items():
                if version == 1:
                    # v1 only ever stored the bare hash string
                    entry[str(tool)] = ToolRecord(hash=str(value), schema=None)
                else:
                    entry[str(tool)] = ToolRecord(
                        hash=str(value["hash"]), schema=value.get("schema")
                    )
            servers[str(name)] = entry
        return cls(version=version, servers=servers)

    def save(self, path: Path) -> None:
        Path(path).write_text(self.to_json(), encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> Lockfile:
        return cls.from_json(Path(path).read_text(encoding="utf-8"))


def build(servers_tools: dict[str, list[dict]]) -> Lockfile:
    servers: dict[str, dict[str, ToolRecord]] = {}
    for server, tools in servers_tools.items():
        entry: dict[str, ToolRecord] = {}
        for tool in tools:
            name = tool.get("name")
            if not name:
                continue
            entry[str(name)] = ToolRecord(hash=hash_tool(tool), schema=_scope_snapshot(tool))
        servers[server] = entry
    return Lockfile(servers=servers)


def diff(old: Lockfile, new: Lockfile) -> list[Finding]:
    """Compare a pinned lockfile against a freshly built one."""
    findings: list[Finding] = []

    if old.version < 2:
        findings.append(
            Finding(
                rule="lock.stale-format",
                severity=Severity.INFO,
                title="Lockfile predates scope-creep classification",
                detail=(
                    "this lock was written by an older mcpwarden and only holds hashes. "
                    "re-run `pin` to also snapshot schemas, so a redefined tool gets "
                    "classified instead of just flagged as changed."
                ),
            )
        )

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

        for tool, new_record in new_tools.items():
            old_record = old_tools.get(tool)
            if old_record is None:
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
            elif old_record.hash != new_record.hash:
                findings.append(
                    Finding(
                        rule="lock.tool-redefined",
                        severity=Severity.HIGH,
                        title=f"Tool definition changed: {server}.{tool}",
                        detail=(
                            f"`{tool}` no longer matches the pinned hash "
                            f"({old_record.hash[:12]}.. -> {new_record.hash[:12]}..). This "
                            f"is the classic rug-pull shape: approve once, mutate later."
                        ),
                        server=server,
                        location=tool,
                    )
                )
                if old_record.schema is not None and new_record.schema is not None:
                    result = _classify_scope_change(old_record.schema, new_record.schema)
                    if result is not None:
                        severity, signals = result
                        findings.append(
                            Finding(
                                rule="scope.widened",
                                severity=severity,
                                title=f"Possible capability increase: {server}.{tool}",
                                detail="; ".join(signals),
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
