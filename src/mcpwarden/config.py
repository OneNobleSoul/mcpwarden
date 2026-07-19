"""Locate and parse the MCP server blocks out of the usual client configs.

Different clients spell the same thing slightly differently:

    Claude Desktop / Cursor / Cline:   {"mcpServers": {"<name>": {...}}}
    VS Code (settings.json):           {"mcp": {"servers": {"<name>": {...}}}}
    plain servers.json:                {"servers": {"<name>": {...}}}

We normalise all of them into ServerSpec.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ServerSpec:
    name: str
    command: str | None = None
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    url: str | None = None  # set for remote (http/sse) servers
    source: Path | None = None

    @property
    def is_remote(self) -> bool:
        return self.url is not None and self.command is None


def default_config_paths() -> list[Path]:
    """Best-effort list of where clients keep their MCP config on this box."""
    home = Path.home()
    candidates: list[Path] = []

    if sys.platform == "darwin":
        app_support = home / "Library" / "Application Support"
        candidates += [
            app_support / "Claude" / "claude_desktop_config.json",
            app_support / "Cursor" / "User" / "settings.json",
            app_support / "Code" / "User" / "settings.json",
            app_support / "Windsurf" / "User" / "settings.json",
        ]
    elif sys.platform.startswith("win"):
        appdata = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
        candidates += [
            appdata / "Claude" / "claude_desktop_config.json",
            appdata / "Cursor" / "User" / "settings.json",
            appdata / "Code" / "User" / "settings.json",
        ]
    else:
        config = Path(os.environ.get("XDG_CONFIG_HOME", home / ".config"))
        candidates += [
            config / "Claude" / "claude_desktop_config.json",
            config / "Cursor" / "User" / "settings.json",
            config / "Code" / "User" / "settings.json",
        ]

    # project-local configs people commit into repos
    cwd = Path.cwd()
    candidates += [
        home / ".cursor" / "mcp.json",
        home / ".codeium" / "windsurf" / "mcp_config.json",
        cwd / ".mcp.json",
        cwd / ".vscode" / "mcp.json",
        cwd / ".cursor" / "mcp.json",
    ]
    return candidates


def _extract_servers_block(data: dict) -> dict:
    if "mcpServers" in data and isinstance(data["mcpServers"], dict):
        return data["mcpServers"]
    if "servers" in data and isinstance(data["servers"], dict):
        return data["servers"]
    mcp = data.get("mcp")
    if isinstance(mcp, dict) and isinstance(mcp.get("servers"), dict):
        return mcp["servers"]
    return {}


def _coerce_args(raw) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, list):
        return [str(a) for a in raw]
    return [str(raw)]


def parse_config(path: Path) -> list[ServerSpec]:
    """Parse a single config file into ServerSpecs. Raises on bad JSON."""
    text = Path(path).read_text(encoding="utf-8")
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a JSON object at the top level")

    servers = []
    for name, spec in _extract_servers_block(data).items():
        if not isinstance(spec, dict):
            continue
        if spec.get("disabled") is True:
            continue
        env = spec.get("env") or {}
        if not isinstance(env, dict):
            env = {}
        servers.append(
            ServerSpec(
                name=name,
                command=spec.get("command"),
                args=_coerce_args(spec.get("args")),
                env={str(k): str(v) for k, v in env.items()},
                url=spec.get("url") or spec.get("serverUrl"),
                source=Path(path),
            )
        )
    return servers


@dataclass
class ConfigError:
    path: Path
    message: str


def discover_configs(paths: list[Path] | None = None) -> tuple[list[ServerSpec], list[ConfigError]]:
    """Parse every readable config we can find.

    Missing files are skipped without comment -- most of the candidate paths
    won't exist on a given box, that's expected. A file that *is* there but
    fails to parse (bad JSON, not an object, unreadable) is different: it's
    a config someone actually has, and staying quiet about it means `scan`
    can come back clean while a broken config sat there unaudited. Those are
    returned as ConfigErrors so the caller can surface them.
    """
    if paths is None:
        paths = default_config_paths()

    found: list[ServerSpec] = []
    errors: list[ConfigError] = []
    seen_files: set[Path] = set()
    for path in paths:
        path = Path(path)
        try:
            resolved = path.resolve()
        except OSError:
            resolved = path
        if resolved in seen_files or not path.is_file():
            continue
        seen_files.add(resolved)
        try:
            found.extend(parse_config(path))
        except (json.JSONDecodeError, OSError, ValueError) as exc:
            errors.append(ConfigError(path=path, message=str(exc)))
    return found, errors


def discover(paths: list[Path] | None = None) -> list[ServerSpec]:
    """Parse every readable config we can find, skipping the ones that aren't there."""
    servers, _ = discover_configs(paths)
    return servers
