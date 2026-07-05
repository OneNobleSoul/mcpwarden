import json

from mcpwarden.config import discover, parse_config


def _write(tmp_path, name, payload):
    p = tmp_path / name
    p.write_text(json.dumps(payload), encoding="utf-8")
    return p


def test_parses_claude_style(tmp_path):
    p = _write(tmp_path, "claude_desktop_config.json", {
        "mcpServers": {
            "files": {"command": "npx", "args": ["-y", "server-filesystem"]},
        }
    })
    servers = parse_config(p)
    assert len(servers) == 1
    assert servers[0].name == "files"
    assert servers[0].command == "npx"
    assert servers[0].args == ["-y", "server-filesystem"]


def test_parses_vscode_nested_style(tmp_path):
    p = _write(tmp_path, "settings.json", {
        "mcp": {"servers": {"git": {"command": "uvx", "args": ["mcp-server-git"]}}}
    })
    servers = parse_config(p)
    assert [s.name for s in servers] == ["git"]


def test_env_and_url_normalised(tmp_path):
    p = _write(tmp_path, "mcp.json", {
        "servers": {
            "remote": {"url": "https://example.com/mcp"},
            "local": {"command": "node", "env": {"API_KEY": 123}},
        }
    })
    by_name = {s.name: s for s in parse_config(p)}
    assert by_name["remote"].is_remote is True
    assert by_name["local"].env == {"API_KEY": "123"}


def test_args_coerced_to_list(tmp_path):
    p = _write(tmp_path, "mcp.json", {"servers": {"x": {"command": "sh", "args": "-c"}}})
    assert parse_config(p)[0].args == ["-c"]


def test_discover_skips_missing_and_broken(tmp_path):
    good = _write(tmp_path, "good.json", {"mcpServers": {"a": {"command": "node"}}})
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    missing = tmp_path / "nope.json"

    servers = discover([good, bad, missing])
    assert [s.name for s in servers] == ["a"]


def test_disabled_server_skipped(tmp_path):
    p = _write(tmp_path, "mcp.json", {
        "mcpServers": {
            "on": {"command": "node"},
            "off": {"command": "node", "disabled": True},
        }
    })
    assert [s.name for s in parse_config(p)] == ["on"]


def test_discover_dedupes_same_file(tmp_path):
    good = _write(tmp_path, "good.json", {"mcpServers": {"a": {"command": "node"}}})
    servers = discover([good, good])
    assert len(servers) == 1
