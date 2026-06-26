"""A deliberately tiny MCP stdio client -- just enough to list tools.

MCP's stdio transport is newline-delimited JSON-RPC 2.0. We do the initialize
handshake, send `notifications/initialized`, then page through `tools/list`.
That's all we need to hash and audit tool definitions; we never call a tool.
"""

from __future__ import annotations

import json
import os
import select
import subprocess
import time
from dataclasses import dataclass, field

from .config import ServerSpec

PROTOCOL_VERSION = "2025-06-18"
CLIENT_INFO = {"name": "mcpwarden", "version": "0"}


class MCPError(RuntimeError):
    pass


@dataclass
class _Conn:
    proc: subprocess.Popen
    _buf: str = ""
    _next_id: int = 0

    def _new_id(self) -> int:
        self._next_id += 1
        return self._next_id

    def send(self, method: str, params: dict | None = None, *, notify: bool = False) -> int | None:
        msg: dict = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        req_id = None
        if not notify:
            req_id = self._new_id()
            msg["id"] = req_id
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()
        return req_id

    def _read_message(self, deadline: float) -> dict:
        assert self.proc.stdout is not None
        fd = self.proc.stdout
        while True:
            nl = self._buf.find("\n")
            if nl != -1:
                line = self._buf[:nl]
                self._buf = self._buf[nl + 1 :]
                line = line.strip()
                if not line:
                    continue
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    # servers sometimes print junk to stdout before speaking json
                    continue

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise MCPError("timed out waiting for server response")
            ready, _, _ = select.select([fd], [], [], remaining)
            if not ready:
                continue
            chunk = os.read(fd.fileno(), 65536)
            if not chunk:
                raise MCPError("server closed the connection")
            self._buf += chunk.decode("utf-8", "replace")

    def await_result(self, req_id: int, timeout: float) -> dict:
        deadline = time.monotonic() + timeout
        while True:
            msg = self._read_message(deadline)
            if msg.get("id") != req_id:
                continue  # a notification or an unrelated response
            if "error" in msg:
                err = msg["error"]
                raise MCPError(f"server error {err.get('code')}: {err.get('message')}")
            return msg.get("result", {})


def _spawn(spec: ServerSpec) -> subprocess.Popen:
    if spec.command is None:
        raise MCPError(f"{spec.name}: no launch command (remote servers aren't supported yet)")
    env = os.environ.copy()
    env.update(spec.env)
    return subprocess.Popen(
        [spec.command, *spec.args],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=env,
        text=True,
        bufsize=1,
    )


def list_tools(spec: ServerSpec, timeout: float = 20.0) -> list[dict]:
    """Launch the server, run the handshake, and return its tool definitions."""
    proc = _spawn(spec)
    conn = _Conn(proc=proc)
    try:
        init_id = conn.send(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": CLIENT_INFO,
            },
        )
        conn.await_result(init_id, timeout)
        conn.send("notifications/initialized", notify=True)

        tools: list[dict] = []
        cursor: str | None = None
        while True:
            params = {"cursor": cursor} if cursor else {}
            req_id = conn.send("tools/list", params)
            result = conn.await_result(req_id, timeout)
            tools.extend(result.get("tools", []))
            cursor = result.get("nextCursor")
            if not cursor:
                break
        return tools
    finally:
        _shutdown(proc)


def _shutdown(proc: subprocess.Popen) -> None:
    for stream in (proc.stdin, proc.stdout):
        try:
            if stream:
                stream.close()
        except OSError:
            pass
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
