"""Background launcher + stdio MCP probe for `idalib-mcp --stdio`.

Spawns `uv run idalib-mcp --stdio <binary>` as a subprocess, drives a minimal
MCP JSON-RPC handshake (initialize, notifications/initialized, tools/list,
idb_list, server_health), and writes the captured output to a file. Designed
to be launched in the background by the calling shell.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: probe_idalib_stdio.py <binary> <output_json>", file=sys.stderr)
        return 2

    binary = Path(sys.argv[1]).resolve()
    out_path = Path(sys.argv[2]).resolve()
    cwd = Path(sys.argv[3]).resolve() if len(sys.argv) > 3 else Path.cwd()

    if not binary.exists():
        out_path.write_text(json.dumps({"error": f"binary not found: {binary}"}))
        return 1

    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"

    cmd = ["uv", "run", "idalib-mcp", "--stdio", str(binary)]
    proc = subprocess.Popen(
        cmd,
        cwd=str(cwd),
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    captured_stdout: list[str] = []
    captured_stderr: list[str] = []

    def _drain(stream, sink):
        for line in stream:
            sink.append(line)

    t_out = threading.Thread(target=_drain, args=(proc.stdout, captured_stdout), daemon=True)
    t_err = threading.Thread(target=_drain, args=(proc.stderr, captured_stderr), daemon=True)
    t_out.start()
    t_err.start()

    def send(req: dict) -> None:
        proc.stdin.write(json.dumps(req) + "\n")
        proc.stdin.flush()

    def recv_lines(n_lines: int, timeout_s: float) -> list[str]:
        """Wait until we have at least n_lines on stdout or timeout."""
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            if len(captured_stdout) >= n_lines:
                return list(captured_stdout[:n_lines])
            time.sleep(0.1)
        return list(captured_stdout[:n_lines])

    def read_message() -> dict | None:
        # MCP framing: newline-delimited JSON in stdio mode.
        deadline = time.monotonic() + 30.0
        while time.monotonic() < deadline:
            while captured_stdout:
                line = captured_stdout.pop(0)
                line = line.strip()
                if not line:
                    continue
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    continue
            if proc.poll() is not None:
                return None
            time.sleep(0.1)
        return None

    responses: dict[str, object] = {}

    # 1. initialize
    send({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "probe", "version": "0.1"},
        },
    })
    responses["initialize"] = read_message()

    # 2. notifications/initialized (no response expected)
    send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})

    # 3. tools/list — give the worker a moment to enumerate tools
    time.sleep(0.5)
    send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    responses["tools/list"] = read_message()

    # 4. idb_list to discover session_id
    send({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
          "params": {"name": "idb_list", "arguments": {}}})
    responses["idb_list"] = read_message()

    session_id = ""
    il = responses["idb_list"]
    if il and "result" in il:
        for block in il["result"].get("content", []):
            if block.get("type") == "text":
                try:
                    parsed = json.loads(block["text"])
                    for s in parsed.get("sessions", []):
                        if "crackme03" in s.get("filename", "").lower():
                            session_id = s["session_id"]
                except Exception:
                    pass

    # 5. server_health with the crackme session
    if session_id:
        send({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
              "params": {"name": "server_health", "arguments": {"database": session_id}}})
        responses["server_health"] = read_message()

        # 6. lookup_funcs for crackme check_pw
        send({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
              "params": {"name": "lookup_funcs", "arguments": {"queries": ["check_pw"], "database": session_id}}})
        responses["lookup_funcs"] = read_message()

        # 7. list_funcs (5 first)
        send({"jsonrpc": "2.0", "id": 6, "method": "tools/call",
              "params": {"name": "list_funcs", "arguments": {"count": 5, "database": session_id}}})
        responses["list_funcs"] = read_message()


    # Ask politely to shut down.
    try:
        proc.stdin.close()
    except Exception:
        pass
    try:
        proc.terminate()
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()

    t_out.join(timeout=2)
    t_err.join(timeout=2)

    payload = {
        "binary": str(binary),
        "returncode": proc.returncode,
        "stderr_tail": "".join(captured_stderr)[-4000:],
        "responses": responses,
    }
    out_path.write_text(json.dumps(payload, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())