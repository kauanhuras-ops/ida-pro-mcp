"""Tests for the top-level stdio proxy server (server.py) and unsafe tool gating."""

import argparse
import contextlib
import json
import os
import sys
from unittest import mock

from ..framework import test
from ..rpc import MCP_SERVER, MCP_UNSAFE

try:
    from ida_pro_mcp import server
except ImportError:
    _parent = os.path.join(os.path.dirname(__file__), "..", "..")
    sys.path.insert(0, _parent)
    try:
        import server  # type: ignore
    finally:
        sys.path.remove(_parent)


class _FakeHttpResponse:
    status = 200
    reason = "OK"

    def __init__(self, body=b'{"jsonrpc":"2.0","result":{}}'):
        self._body = body

    def read(self):
        return self._body


class _RecordingConnection:
    calls = []

    def __init__(self, host, port, timeout=None):
        self.host = host
        self.port = port
        self.timeout = timeout

    def request(self, method, path, body=None, headers=None):
        self.__class__.calls.append(
            {
                "host": self.host,
                "port": self.port,
                "timeout": self.timeout,
                "method": method,
                "path": path,
                "body": body,
                "headers": headers or {},
            }
        )

    def getresponse(self):
        return _FakeHttpResponse()

    def close(self):
        pass


@contextlib.contextmanager
def _saved_target():
    """Preserve the currently configured IDA target across assertions."""
    old_host = server.IDA_HOST
    old_port = server.IDA_PORT
    old_session = getattr(server.mcp._transport_session_id, "data", None)
    old_exts = getattr(server.mcp._enabled_extensions, "data", set())
    try:
        yield
    finally:
        server.IDA_HOST = old_host
        server.IDA_PORT = old_port
        server.mcp._transport_session_id.data = old_session
        server.mcp._enabled_extensions.data = old_exts


@test()
def test_streamable_http_initialize_returns_session_id():
    """Streamable HTTP initialize should issue a session id for per-client state."""
    test_mcp = server.McpServer("session-test")
    test_mcp.serve("127.0.0.1", 0, request_handler=server.McpHttpRequestHandler)
    port = test_mcp._http_server.server_address[1]
    conn = server.http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        payload = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1.0"},
                },
            }
        )
        conn.request("POST", "/mcp", payload, {"Content-Type": "application/json"})
        response = conn.getresponse()
        response.read()
        session_id = response.getheader("Mcp-Session-Id")
        assert response.status == 200
        assert session_id, "Expected initialize response to include Mcp-Session-Id"
        assert test_mcp.has_http_session(session_id)
    finally:
        conn.close()
        test_mcp.stop()


@test()
def test_server_proxy_to_ida_forwards_session_and_extensions():
    """Proxy requests should preserve MCP session and enabled extensions."""
    with _saved_target():
        original_conn = server.http.client.HTTPConnection
        _RecordingConnection.calls = []
        server.http.client.HTTPConnection = _RecordingConnection
        server.IDA_HOST = "127.0.0.1"
        server.IDA_PORT = 13337
        server.mcp._transport_session_id.data = "http:session-456"
        server.mcp._enabled_extensions.data = {"dbg"}
        try:
            server._proxy_to_ida(b"{}", server.IDA_HOST, server.IDA_PORT)
            assert len(_RecordingConnection.calls) == 1
            call = _RecordingConnection.calls[0]
            assert call["path"] == "/mcp?ext=dbg"
            assert call["headers"].get("Mcp-Session-Id") == "session-456"
        finally:
            server.http.client.HTTPConnection = original_conn


class _FakeToolsListConn:
    """Stand-in for HTTPConnection that returns a canned tools/list response."""

    def __init__(self, host, port, timeout=None):
        pass

    def request(self, method, url, body=None, headers=None):
        pass

    def getresponse(self_inner):  # noqa: N805
        class R:
            status = 200
            reason = "OK"

            def read(inner):
                return (
                    b'{"jsonrpc":"2.0","id":1,'
                    b'"result":{"tools":[{"name":"decompile",'
                    b'"description":"Decompile at addr"},'
                    b'{"name":"list_funcs","description":"List functions"}]}}'
                )

        return R()

    def close(self):
        pass


@test()
def test_dispatch_proxy_tools_list_includes_proxy_local_tools():
    """tools/list must merge IDA tools with proxy-local idb_list / idb_select.

    Before this fix the proxy forwarded tools/list to the IDA verbatim, so the
    proxy-local routing tools were never advertised to the agent and stayed
    invisible after a fresh Claude Code session connected.
    """
    with _saved_target():
        original_conn = server.http.client.HTTPConnection
        server.http.client.HTTPConnection = _FakeToolsListConn
        server.IDA_HOST = "127.0.0.1"
        server.IDA_PORT = 13337
        try:
            response = server.dispatch_proxy(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/list",
                    "params": {},
                }
            )
            assert response is not None
            tools = response.get("result", {}).get("tools", [])
            names = {t["name"] for t in tools}
        finally:
            server.http.client.HTTPConnection = original_conn

    assert "decompile" in names, tools
    assert "list_funcs" in names, tools
    assert "idb_list" in names, f"proxy-local idb_list missing: {names}"
    assert "idb_select" in names, f"proxy-local idb_select missing: {names}"


class _AlwaysRefuseConn:
    def __init__(self, host, port, timeout=None):
        pass

    def request(self, method, url, body=None, headers=None):
        raise ConnectionRefusedError("no IDA")

    def getresponse(self_inner):  # noqa: N805
        raise AssertionError

    def close(self):
        pass


@test()
def test_dispatch_proxy_tools_list_falls_back_to_local_when_ida_down():
    """If the IDA is unreachable on tools/list, still show local tools so the
    agent can recover via idb_list once an IDA comes back up."""
    with _saved_target():
        original_conn = server.http.client.HTTPConnection
        server.http.client.HTTPConnection = _AlwaysRefuseConn
        server.IDA_HOST = "127.0.0.1"
        server.IDA_PORT = 13337
        # Shrink the recovery loop so the test doesn't wait the full 30s.
        original_timeout = server.routing.RECOVERY_TIMEOUT_SEC
        original_poll = server.routing.RECOVERY_POLL_INTERVAL_SEC
        server.routing.RECOVERY_TIMEOUT_SEC = 0.05
        server.routing.RECOVERY_POLL_INTERVAL_SEC = 0.01
        try:
            response = server.dispatch_proxy(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/list",
                    "params": {},
                }
            )
            assert response is not None
            tools = response.get("result", {}).get("tools", [])
            names = {t["name"] for t in tools}
        finally:
            server.routing.RECOVERY_TIMEOUT_SEC = original_timeout
            server.routing.RECOVERY_POLL_INTERVAL_SEC = original_poll
            server.http.client.HTTPConnection = original_conn

    assert "idb_list" in names, names
    assert "idb_select" in names, names


@test()
def test_dispatch_proxy_idb_call_handled_locally():
    """tools/call for idb_list / idb_select never forwards to the IDA."""
    with _saved_target():
        original_conn = server.http.client.HTTPConnection
        _RecordingConnection.calls = []
        server.http.client.HTTPConnection = _RecordingConnection
        server.IDA_HOST = "127.0.0.1"
        server.IDA_PORT = 13337
        try:
            # Stub discover_instances so idb_list returns a deterministic set.
            with mock.patch.object(
                server, "discover_instances", return_value=[]
            ):
                response = server.dispatch_proxy(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {"name": "idb_list", "arguments": {}},
                    }
                )
        finally:
            server.http.client.HTTPConnection = original_conn

    assert response is not None
    assert _RecordingConnection.calls == [], (
        "idb_list must not be forwarded to the IDA"
    )
    instances = response.get("result", {}).get("structuredContent", {}).get(
        "instances", None
    )
    if instances is None:
        # Older schemas: result is the dict directly.
        instances = response.get("result", {}).get("instances", [])
    assert isinstance(instances, list)


@test()
def test_resolve_ida_rpc_preserves_ext_query_param():
    """--ida-rpc http://host:port/mcp?ext=dbg should seed enabled extensions."""
    with _saved_target():
        args = argparse.Namespace(ida_rpc="http://10.0.0.1:9999/mcp?ext=dbg")
        server._resolve_ida_rpc(args)
        assert server.IDA_HOST == "10.0.0.1"
        assert server.IDA_PORT == 9999
        exts = getattr(server.mcp._enabled_extensions, "data", set())
        assert "dbg" in exts, f"Expected 'dbg' in enabled extensions, got: {exts}"


@test()
def test_resolve_ida_rpc_preserves_multiple_ext_query_params():
    """--ida-rpc with ext=dbg,extra should seed both extensions."""
    with _saved_target():
        args = argparse.Namespace(ida_rpc="http://10.0.0.1:9999/mcp?ext=dbg,extra")
        server._resolve_ida_rpc(args)
        exts = getattr(server.mcp._enabled_extensions, "data", set())
        assert "dbg" in exts, f"Expected 'dbg' in extensions, got: {exts}"
        assert "extra" in exts, f"Expected 'extra' in extensions, got: {exts}"


@test()
def test_resolve_ida_rpc_no_ext_leaves_extensions_empty():
    """--ida-rpc without ext param should not add spurious extensions."""
    with _saved_target():
        server.mcp._enabled_extensions.data = set()
        args = argparse.Namespace(ida_rpc="http://10.0.0.1:9999")
        server._resolve_ida_rpc(args)
        exts = getattr(server.mcp._enabled_extensions, "data", set())
        assert len(exts) == 0, f"Expected no extensions, got: {exts}"


@test()
def test_ida_rpc_ext_flows_through_to_proxy_path():
    """Extensions from --ida-rpc should appear in proxied request path."""
    with _saved_target():
        original_conn = server.http.client.HTTPConnection
        _RecordingConnection.calls = []
        server.http.client.HTTPConnection = _RecordingConnection
        try:
            args = argparse.Namespace(ida_rpc="http://10.0.0.1:9999/mcp?ext=dbg")
            server._resolve_ida_rpc(args)
            server._proxy_to_ida(b"{}", server.IDA_HOST, server.IDA_PORT)
            assert len(_RecordingConnection.calls) == 1
            assert _RecordingConnection.calls[0]["path"] == "/mcp?ext=dbg"
        finally:
            server.http.client.HTTPConnection = original_conn


# ---------------------------------------------------------------------------
# Unsafe tool gating (idalib registry-removal approach, mirrors idalib_server)
# ---------------------------------------------------------------------------


@contextlib.contextmanager
def _saved_tools():
    """Save and restore the tools registry so removal tests are non-destructive."""
    original = MCP_SERVER.tools.methods.copy()
    try:
        yield
    finally:
        MCP_SERVER.tools.methods = original


@test()
def test_unsafe_tools_registered():
    """@unsafe decorator should populate MCP_UNSAFE with known tool names."""
    assert len(MCP_UNSAFE) > 0, "MCP_UNSAFE is empty — no tools marked @unsafe"
    assert "py_eval" in MCP_UNSAFE, "py_eval should be marked @unsafe"
    assert "py_exec_file" in MCP_UNSAFE, "py_exec_file should be marked @unsafe"


@test()
def test_unsafe_tools_present_by_default():
    """Unsafe tools should be in the registry by default (plugin behavior)."""
    tool_names = set(MCP_SERVER.tools.methods)
    for name in ("py_eval", "py_exec_file"):
        assert name in tool_names, f"{name} should be present by default"


@test()
def test_unsafe_tools_hidden_after_removal():
    """tools/list should exclude tools removed from the registry (idalib --unsafe behavior)."""
    with _saved_tools():
        for name in MCP_UNSAFE:
            MCP_SERVER.tools.methods.pop(name, None)
        result = MCP_SERVER._mcp_tools_list()
        tool_names = {t["name"] for t in result.get("tools", [])}
        leaked = MCP_UNSAFE & tool_names
        assert not leaked, f"Removed unsafe tools still listed: {leaked}"


@test()
def test_unsafe_tool_call_rejected_after_removal():
    """tools/call for a removed tool should return an error."""
    with _saved_tools():
        for name in MCP_UNSAFE:
            MCP_SERVER.tools.methods.pop(name, None)
        result = MCP_SERVER._mcp_tools_call("py_eval", {"code": "pass"})
        assert result.get("isError"), f"Expected error for removed tool, got: {result}"


@test()
def test_safe_tools_unaffected_by_unsafe_removal():
    """Non-unsafe tools should remain callable after unsafe removal."""
    with _saved_tools():
        for name in MCP_UNSAFE:
            MCP_SERVER.tools.methods.pop(name, None)
        assert "decompile" not in MCP_UNSAFE, "decompile should not be unsafe"
        assert "decompile" in MCP_SERVER.tools.methods, "decompile should survive removal"
