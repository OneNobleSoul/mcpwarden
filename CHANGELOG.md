# Changelog

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
