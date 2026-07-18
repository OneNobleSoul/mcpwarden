# mcpwarden

[![CI](https://github.com/OneNobleSoul/mcpwarden/actions/workflows/ci.yml/badge.svg)](https://github.com/OneNobleSoul/mcpwarden/actions/workflows/ci.yml)
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
- capability increases hiding inside a "changed" tool — new required params,
  loosened schemas, unsafe annotation flips (see below)

Findings have a severity and a stable `rule` id, so you can grep them or gate on
`--fail-on`.

## Shadow tools

`inspect` and `verify` also compare tool names and descriptions **across** every
server in your config. MCP has no cryptographic tool identity — a client tells
two tools apart by name alone — so nothing stops a second server from exposing
a tool called `read_file` that collides with, or closely imitates, one you
already trust.

- an exact name collision between two different servers is always flagged
  (`shadow.name-collision`); severity depends on whether the descriptions also
  match — two legitimate servers offering the same tool read as low, a
  mismatch is worth a second look
- a name that's close-but-not-identical (`readFile` vs `read_file`, a typo, an
  extra character) combined with a similar description is flagged high
  (`shadow.name-similar`) — that combination is the shape of a typosquat, not
  a coincidence
- tools within the same server are never compared against each other, and
  short/generic names need more than fuzzy similarity before they're trusted

This needs no lockfile and no extra connections — it runs on whatever
`inspect`/`verify` already pulled from `tools/list`.

## The lockfile

`mcpwarden.lock` is JSON, `server -> tool -> { hash, schema }`. The hash covers
the whole tool definition except the display-only `title`, so any change to a
description or input schema moves it. Commit it next to your MCP config and
`verify` becomes a diff you can trust.

`schema` is a small snapshot (required params, enum constraints,
`additionalProperties`, annotations, description) kept alongside the hash so a
redefined tool doesn't just get flagged as "changed" — `verify` can tell you
*what* changed. When a hash moves, `scope.widened` looks at the specific
signals: a param that became required, an enum losing values,
`additionalProperties` going from `false` to open, a new parameter named like
a capability (`force`, `recursive`, `bypass`, ...), or a tool annotation
flipping from safe to unsafe (`readOnlyHint` dropped, `destructiveHint`
newly set). A single weak signal stays quiet — a typo fix shouldn't page
anyone — severity only climbs when independent signals line up.

Lockfiles from before this landed only hold hashes. They keep working exactly
as before (`lock.tool-redefined` still fires), just without the extra
classification; `verify` leaves a one-time `lock.stale-format` note nudging a
re-pin.

## Limitations / notes

- Remote (HTTP/SSE) servers are discovered but not yet inspected — stdio only for now.
- Heuristics are heuristics: they'll miss cleverly worded poisoning and can flag
  a blunt-but-legit description. It's a smoke alarm, not a proof.
- Prior art worth knowing: Invariant Labs' `mcp-scan`. mcpwarden leans harder on
  the lockfile/rug-pull angle and runs fully local with a tiny dependency surface.

## License

MIT
