# Changelog

## 0.3.0

- `inspect`/`verify` now compare tool names and descriptions across all
  configured servers and flag exact name collisions and near-identical
  (fuzzy name + description) matches between different servers — MCP tool
  shadowing/typosquatting

## 0.2.1

- detect Unicode tag-block characters (U+E0000-U+E007F) in tool
  descriptions/schemas and decode them — this is the "ASCII smuggling"
  trick, invisible in every font but readable 1:1 as ASCII once you know
  the offset

## 0.2.0

- `inspect`, `pin` and `verify` commands backed by a minimal stdio MCP client
- lockfile with rug-pull detection (changed/added/removed tool definitions)
- poison heuristics over tool descriptions and schemas (instruction-shaped text,
  hidden/zero-width unicode)
- `--json` output and `--fail-on` threshold for CI
- more hardcoded-secret patterns (stripe, gitlab, npm)

## 0.1.0

- initial `scan` command: static audit of client configs
- secret + risky-launch-command detectors
- config discovery for Claude Desktop / Cursor / VS Code style files
