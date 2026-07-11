# mcpwarden

[![CI](https://github.com/UnterwegsDev/mcpwarden/actions/workflows/ci.yml/badge.svg)](https://github.com/UnterwegsDev/mcpwarden/actions/workflows/ci.yml)
![python](https://img.shields.io/badge/python-3.11%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)

Audit the MCP servers you've wired into your local clients (Claude Desktop,
Cursor, VS Code, Windsurf, ...) before they audit you.

Most people install an MCP server by pasting an `mcpServers` block from some
README and never look at it again. Two things go wrong with that:

1. The launch command or env is sketchy from day one — a hardcoded token, a
   `curl | bash`, an unpinned `npx` that pulls whatever's latest.
2. The server behaves at install time and **changes its tool definitions later**.
   MCP clients don't diff tool descriptions between sessions, so a server can
   quietly slip a hidden instruction into a description after you've approved it
   (a "rug pull"). Tool poisoning only has to land once.

`mcpwarden` covers both: a static pass over the config, and a lockfile that pins
tool definitions so the second one can't happen without you hearing about it.

## Install

```
pipx install mcpwarden
# or, from a clone:
pip install -e .
```

Python 3.11+. The only runtime dependency is `rich`.

## Usage

Static audit of every config it can find:

```
mcpwarden scan
```

Point it at a specific config:

```
mcpwarden scan -c ~/Library/Application\ Support/Claude/claude_desktop_config.json
```

Connect to the servers and look at the tools they actually expose:

```
mcpwarden inspect
```

Pin the current tool definitions, then check them later:

```
mcpwarden pin              # writes mcpwarden.lock
mcpwarden verify           # re-reads live tools, diffs against the lock
```

`verify` is the one to wire into CI or a cron job. It exits non-zero when a
pinned tool definition has changed, a new tool appeared, or a description trips
the poison heuristics:

```
mcpwarden verify --fail-on high --json
```

## What it flags

**Config (static):**

- hardcoded credentials in `env` (AWS/GitHub/OpenAI/Slack/Google keys, private keys)
- launch through `sh -c`, or fetch-and-execute (`curl … | bash`)
- unpinned `npx`/`uvx`/`pipx` runners that resolve the package at launch

**Tool definitions (live):**

- instruction-shaped text aimed at the model ("ignore previous…", "do not tell
  the user…", `<important>` blocks, references to reading `~/.ssh` / `.env`)
- invisible/zero-width and bidi characters hidden inside descriptions or schemas
- Unicode tag-block characters (the ASCII-smuggling trick) — decoded and shown
  in the finding, not just flagged
- changed / added / removed tools versus the lockfile (rug-pull detection)

Findings have a severity and a stable `rule` id, so you can grep them or gate on
`--fail-on`.

## The lockfile

`mcpwarden.lock` is a plain JSON map of `server -> tool -> sha256`. The hash
covers the whole tool definition except the display-only `title`, so any change
to a description or input schema moves it. Commit it next to your MCP config and
`verify` becomes a diff you can trust.

## Limitations / notes

- Remote (HTTP/SSE) servers are discovered but not yet inspected — stdio only for now.
- Heuristics are heuristics: they'll miss cleverly worded poisoning and can flag
  a blunt-but-legit description. It's a smoke alarm, not a proof.
- Prior art worth knowing: Invariant Labs' `mcp-scan`. mcpwarden leans harder on
  the lockfile/rug-pull angle and runs fully local with a tiny dependency surface.

## License

MIT
