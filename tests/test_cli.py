import argparse
import json

from mcpwarden.cli import _resolve_servers


def _args(tmp_path, *config_paths):
    return argparse.Namespace(config=[str(p) for p in config_paths] or None, server=None)


def test_resolve_servers_surfaces_config_parse_error(tmp_path):
    good = tmp_path / "good.json"
    good.write_text(json.dumps({"mcpServers": {"a": {"command": "node"}}}), encoding="utf-8")
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")

    servers, findings = _resolve_servers(_args(tmp_path, good, bad))

    assert [s.name for s in servers] == ["a"]
    assert len(findings) == 1
    assert findings[0].rule == "config.parse-error"
    assert str(bad) in (findings[0].location or "")


def test_resolve_servers_no_findings_when_all_configs_parse(tmp_path):
    good = tmp_path / "good.json"
    good.write_text(json.dumps({"mcpServers": {"a": {"command": "node"}}}), encoding="utf-8")

    servers, findings = _resolve_servers(_args(tmp_path, good))

    assert [s.name for s in servers] == ["a"]
    assert findings == []
