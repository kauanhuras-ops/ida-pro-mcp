"""Pure-Python proxy routing helpers.

The proxy server (see ``ida_pro_mcp/server.py``) uses these helpers to
maintain per-MCP-session routing state and to handle ``idb_list`` /
``idb_select`` locally without forwarding to any single IDA. This module
is deliberately free of ``ida_mcp.*`` imports so it can be unit-tested
without an IDA installation.
"""
from __future__ import annotations

import http.client
import json
import threading
import time
from typing import Callable

# Default endpoint (matches ``server.py:DEFAULT_IDA_HOST/PORT``).
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 13337

# Recovery window when the targeted IDA is unreachable. The proxy polls the
# port every ``_RECOVERY_POLL_INTERVAL_SEC`` until either the connection
# succeeds or the deadline elapses.
RECOVERY_TIMEOUT_SEC = 30.0
RECOVERY_POLL_INTERVAL_SEC = 0.5


class SessionTargets:
    """Per-session routing table keyed by an opaque session id string.

    The proxy derives the session id from
    ``MCP_SERVER.get_current_transport_session_id()`` for each request.
    A small thread-safe wrapper covers concurrent HTTP handler threads.
    """

    def __init__(self) -> None:
        self._targets: dict[str, tuple[str, int, str]] = {}
        self._lock = threading.Lock()

    def get(self, session_id: str) -> tuple[str, int, str] | None:
        with self._lock:
            return self._targets.get(session_id)

    def set(self, session_id: str, host: str, port: int, idb_path: str) -> None:
        with self._lock:
            self._targets[session_id] = (host, port, idb_path)

    def clear(self) -> None:
        with self._lock:
            self._targets.clear()


def list_instances_to_response(
    instances: list[dict],
    *,
    current: tuple[str, int, str],
) -> dict:
    """Format ``discover_instances()`` output for the ``idb_list`` tool response.

    Mark the entry that matches ``current`` (host, port) so the agent can tell
    at a glance which IDA its session is pinned to.
    """
    cur_host, cur_port, _ = current
    items = []
    for inst in instances:
        is_current = inst.get("host") == cur_host and inst.get("port") == cur_port
        items.append(
            {
                "idb_path": inst.get("idb_path", ""),
                "binary": inst.get("binary", ""),
                "host": inst.get("host", "127.0.0.1"),
                "port": int(inst.get("port", 0)),
                "pid": int(inst.get("pid", 0)) if inst.get("pid") is not None else 0,
                "backend": inst.get("backend", "gui"),
                "current": is_current,
            }
        )
    items.sort(key=lambda x: x["idb_path"] or x["binary"])
    return {"instances": items}


def select_target(
    target: str,
    instances: list[dict],
    *,
    set_target: Callable[[str, int, str], None],
) -> dict:
    """Pick one running IDA and pin it for the current session.

    Matching priority: exact ``idb_path`` first, then numeric ``port``
    fallback. ``set_target(host, port, idb_path)`` is called on success.
    """
    target_str = (target or "").strip()

    match = None
    for inst in instances:
        if inst.get("idb_path") and inst.get("idb_path") == target_str:
            match = inst
            break
    if match is None and target_str.isdigit():
        port = int(target_str)
        for inst in instances:
            if int(inst.get("port", 0)) == port:
                match = inst
                break
    if match is None:
        available = ", ".join(
            f"{i.get('idb_path') or '<no idb>'} (port {i.get('port')})"
            for i in instances
        )
        return {
            "error": (
                f"No IDA instance matches target {target_str!r}. "
                f"Available: [{available}]. "
                "Run idb_list to see all running instances."
            )
        }

    host = match.get("host", "127.0.0.1")
    port = int(match.get("port"))
    idb_path = match.get("idb_path", "")
    set_target(host, port, idb_path)
    return {
        "current": {
            "idb_path": idb_path,
            "host": host,
            "port": port,
            "binary": match.get("binary", ""),
        }
    }


def forward_json_rpc(
    payload: bytes | str | dict,
    *,
    host: str,
    port: int,
    path: str,
    headers: dict,
    conn_factory: Callable[..., http.client.HTTPConnection] | None = None,
    response_factory: Callable[[http.client.HTTPResponse], bytes] | None = None,
    sleep: Callable[[float], None] | None = None,
    now: Callable[[], float] | None = None,
    timeout_sec: float = RECOVERY_TIMEOUT_SEC,
    poll_interval_sec: float = RECOVERY_POLL_INTERVAL_SEC,
) -> dict:
    """POST a JSON-RPC payload to ``host:port`` and return the parsed reply.

    On connection-level failures (``ConnectionRefusedError`` /
    ``ConnectionResetError`` / ``OSError``) the call polls the port until
    ``timeout_sec`` elapses, then re-raises. HTTP-level errors (4xx/5xx)
    propagate immediately — those are authoritative responses, not a sign
    that the server is restarting.
    """
    # Resolve callables at call time, not definition time, so test stubs that
    # monkey-patch ``http.client.HTTPConnection`` (or any of the helpers)
    # after this module was imported still take effect.
    if conn_factory is None:
        conn_factory = http.client.HTTPConnection
    if response_factory is None:
        response_factory = lambda r: r.read()
    if sleep is None:
        sleep = time.sleep
    if now is None:
        now = time.monotonic

    if isinstance(payload, dict):
        payload = json.dumps(payload)
    if isinstance(payload, str):
        payload = payload.encode("utf-8")

    deadline = now() + timeout_sec
    attempt = 0
    while True:
        attempt += 1
        conn = conn_factory(host, port, timeout=30)
        try:
            try:
                conn.request("POST", path, payload, headers)
                response = conn.getresponse()
                raw = response_factory(response)
                if hasattr(response, "status") and response.status >= 400:
                    reason = getattr(response, "reason", "")
                    raise RuntimeError(f"HTTP {response.status} {reason}: {raw!r}")
                return json.loads(raw)
            except (ConnectionRefusedError, ConnectionResetError, OSError):
                if now() >= deadline:
                    raise
                sleep(poll_interval_sec)
                continue
        finally:
            conn.close()
