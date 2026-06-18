"""Static checks over a parsed MCP config.

Nothing here launches a server -- it's purely what we can tell from the config
block itself. The stuff that needs a live connection lives in mcpclient.py.
"""

from __future__ import annotations

import re

from .config import ServerSpec
from .findings import Finding, Severity

# Token shapes that are unambiguous enough to flag as a hardcoded secret.
SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[posru]_[A-Za-z0-9]{36,}\b")),
    ("github-pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b")),
    ("openai-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("private-key-block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
]

# env keys that read like a credential
SECRET_KEY_HINT = re.compile(r"(?:_|\b)(TOKEN|SECRET|PASSWORD|PASSWD|APIKEY|API_KEY|ACCESS_KEY)\b", re.I)

# values that clearly aren't a real secret, so we don't cry wolf
PLACEHOLDER = re.compile(
    r"^\s*(\$\{.*\}|<.*>|your[_-].*|xxx+|changeme|placeholder|todo|\.\.\.|)\s*$", re.I
)

_SHELLS = {"sh", "bash", "zsh", "dash", "ksh"}
_FETCHERS = {"curl", "wget"}
_RUNNERS = {"npx", "uvx", "uv", "pipx", "bunx", "pnpm", "yarn"}


def _basename(cmd: str) -> str:
    return cmd.replace("\\", "/").rsplit("/", 1)[-1].lower()


def scan_env(spec: ServerSpec) -> list[Finding]:
    out: list[Finding] = []
    for key, value in spec.env.items():
        if PLACEHOLDER.match(value or ""):
            continue
        matched = None
        for name, pat in SECRET_PATTERNS:
            if pat.search(value):
                matched = name
                break
        if matched:
            out.append(
                Finding(
                    rule="secret.hardcoded",
                    severity=Severity.HIGH,
                    title=f"Hardcoded {matched} in env",
                    detail=(
                        f"{spec.name}.env[{key}] contains what looks like a live "
                        f"{matched}. Reference it from the environment instead of "
                        f"pinning it in the config."
                    ),
                    server=spec.name,
                    location=key,
                )
            )
        elif SECRET_KEY_HINT.search(key) and value and not PLACEHOLDER.match(value):
            out.append(
                Finding(
                    rule="secret.inline-credential",
                    severity=Severity.MEDIUM,
                    title=f"Credential-looking value set inline for {key}",
                    detail=(
                        f"{spec.name}.env[{key}] holds an inline value. If that's a "
                        f"real credential it will sit in plaintext in your client config."
                    ),
                    server=spec.name,
                    location=key,
                )
            )
    return out


def scan_command(spec: ServerSpec) -> list[Finding]:
    if spec.command is None:
        return []
    out: list[Finding] = []
    base = _basename(spec.command)
    joined = " ".join(spec.args)

    if base in _SHELLS and any(a in ("-c", "-lc", "-ic") for a in spec.args):
        out.append(
            Finding(
                rule="command.shell-c",
                severity=Severity.HIGH,
                title=f"Server launches through `{base} -c`",
                detail=(
                    f"{spec.name} starts an inline shell command. Whatever is in there "
                    f"runs with your privileges every time the client boots the server."
                ),
                server=spec.name,
                location=spec.command,
            )
        )

    if base in _FETCHERS or re.search(r"\b(curl|wget)\b.*\|\s*(sh|bash)", joined):
        out.append(
            Finding(
                rule="command.curl-pipe-shell",
                severity=Severity.CRITICAL,
                title="Fetch-and-execute in launch command",
                detail=(
                    f"{spec.name} pulls something over the network and runs it. That's a "
                    f"remote-code-execution primitive baked into your startup path."
                ),
                server=spec.name,
                location=spec.command,
            )
        )

    if base in _RUNNERS:
        pinned = any("@" in a and not a.startswith("@") for a in spec.args)
        if not pinned:
            out.append(
                Finding(
                    rule="command.unpinned-runner",
                    severity=Severity.MEDIUM,
                    title=f"`{base}` resolves the package at runtime",
                    detail=(
                        f"{spec.name} runs via {base} without a pinned version, so it "
                        f"fetches whatever is latest at launch. A compromised release "
                        f"lands with no diff on your side."
                    ),
                    server=spec.name,
                    location=spec.command,
                )
            )
    return out


def scan_server(spec: ServerSpec) -> list[Finding]:
    findings = scan_env(spec)
    findings += scan_command(spec)
    return findings


def scan_servers(specs: list[ServerSpec]) -> list[Finding]:
    out: list[Finding] = []
    for spec in specs:
        out.extend(scan_server(spec))
    return out
