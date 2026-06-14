# mcpwarden

Small CLI to audit the MCP servers you've got wired into your local clients
(Claude Desktop, Cursor, VS Code, ...). Early days, see TODO.

Idea: most of us copy an `mcpServers` block from some README into our config and
never look at it again. This checks the config for the obvious foot-guns and
(later) pins tool definitions so a server can't quietly change them on you.

## TODO
- [ ] parse the common client configs
- [ ] flag hardcoded secrets / sketchy launch commands
- [ ] pin + verify tool definitions (rug-pull detection)
- [ ] tests, CI
