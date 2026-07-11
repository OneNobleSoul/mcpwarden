"""Static checks over a parsed MCP config.

Nothing here launches a server -- it's purely what we can tell from the config
block itself. The stuff that needs a live connection lives in mcpclient.py.
"""

from __future__ import annotations

import json
import re
import unicodedata

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
    ("stripe-key", re.compile(r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("gitlab-pat", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b")),
    ("npm-token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("private-key-block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
]

# env keys that read like a credential
SECRET_KEY_HINT = re.compile(
    r"(?:_|\b)(TOKEN|SECRET|PASSWORD|PASSWD|APIKEY|API_KEY|ACCESS_KEY)\b", re.I
)

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


# --- tool-definition heuristics (need a live `tools/list`) -----------------

# Instruction-shaped phrases aimed at the model rather than the human reader.
INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("override", re.compile(r"ignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above)", re.I)),
    ("override", re.compile(r"disregard\s+(?:all\s+|the\s+)?(?:previous|prior|earlier)", re.I)),
    ("secrecy", re.compile(r"do\s+not\s+(?:tell|mention|inform|reveal|show)\b", re.I)),
    ("secrecy", re.compile(r"without\s+(?:telling|informing|notifying)\s+the\s+user", re.I)),
    ("exfil", re.compile(r"(?:read|cat|send|upload|exfiltrat\w*).{0,40}(?:~/\.ssh|id_rsa|\.env|"
                          r"credentials|secret|api[_-]?key)", re.I)),
    ("directive", re.compile(r"<(?:important|system|instructions?|secret)>", re.I)),
    ("directive", re.compile(r"\byou\s+must\s+(?:always|never|also)\b", re.I)),
]

# zero-width, bidi overrides, BOM -- classic places to smuggle text
_HIDDEN = re.compile(
    "["
    "​-‏"  # zero-width space/joiners, LRM/RLM
    "‪-‮"  # bidi embedding/override
    "⁠-⁤"  # word joiner, invisible operators
    "⁦-⁩"  # bidi isolates
    "﻿"         # BOM / zero-width no-break space
    "]"
)

# Unicode tag block (U+E0000-U+E007F). Invented for defunct language tags,
# now mostly known for "ASCII smuggling": tag chars mirror the printable
# ASCII range 1:1 (codepoint - 0xE0000), render as nothing in any font
# we've checked, and can carry a full sentence of hidden instructions.
_TAG_CHARS = re.compile("[\U000e0000-\U000e007f]")


def _decode_tags(text: str) -> str:
    """Best-effort decode of a tag-character run back to the ASCII it hides."""
    out = []
    for ch in text:
        code = ord(ch)
        if 0xE0020 <= code <= 0xE007E:
            out.append(chr(code - 0xE0000))
        elif code in (0xE0000, 0xE007F):
            continue  # cancel tag / unused base -- nothing printable
        else:
            out.append("?")
    return "".join(out).strip()


def _tool_text(tool: dict) -> str:
    """Everything a model would actually read out of a tool definition."""
    parts = [str(tool.get("description", ""))]
    schema = tool.get("inputSchema") or tool.get("input_schema")
    if isinstance(schema, dict):
        parts.append(json.dumps(schema, ensure_ascii=False))
    for key in ("annotations", "_meta"):
        if key in tool:
            parts.append(json.dumps(tool[key], ensure_ascii=False))
    return "\n".join(parts)


def scan_text(text: str, *, server: str | None, location: str | None) -> list[Finding]:
    out: list[Finding] = []
    seen: set[str] = set()
    for kind, pat in INJECTION_PATTERNS:
        m = pat.search(text)
        if m and kind not in seen:
            seen.add(kind)
            out.append(
                Finding(
                    rule=f"poison.{kind}",
                    severity=Severity.HIGH,
                    title=f"Instruction-like text in tool definition ({kind})",
                    detail=(
                        f"matched {m.group(0)!r}. Tool definitions get fed to the model "
                        f"verbatim, so wording like this is how tool poisoning works."
                    ),
                    server=server,
                    location=location,
                )
            )

    hidden = _HIDDEN.findall(text)
    if hidden:
        names = ", ".join(sorted({unicodedata.name(c, hex(ord(c))) for c in hidden}))
        out.append(
            Finding(
                rule="poison.hidden-unicode",
                severity=Severity.HIGH,
                title="Hidden/invisible characters in tool definition",
                detail=(
                    f"found {len(hidden)} invisible char(s): {names}. These render as "
                    f"nothing to you but still reach the model -- a common way to hide "
                    f"instructions inside an otherwise innocent description."
                ),
                server=server,
                location=location,
            )
        )

    tags = _TAG_CHARS.findall(text)
    if tags:
        decoded = _decode_tags("".join(tags))
        detail = (
            f"found {len(tags)} Unicode tag character(s) -- invisible in every font "
            f"we've checked."
        )
        if decoded:
            detail += f" decoded, they read: {decoded!r}"
        out.append(
            Finding(
                rule="poison.hidden-unicode-tags",
                severity=Severity.CRITICAL,
                title="Unicode tag-block smuggling in tool definition",
                detail=detail,
                server=server,
                location=location,
            )
        )
    return out


def scan_tool(server: str, tool: dict) -> list[Finding]:
    name = str(tool.get("name", "<unnamed>"))
    return scan_text(_tool_text(tool), server=server, location=name)


def scan_tools(server: str, tools: list[dict]) -> list[Finding]:
    out: list[Finding] = []
    for tool in tools:
        out.extend(scan_tool(server, tool))
    return out
