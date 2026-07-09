"""Tests for ida_mcp.dispatcher.

These run outside IDA: the module uses lazy imports for IDA-specific deps.
"""

import json
import http.server
import pathlib
import sys
import threading
import pytest

# Add ida_mcp to path so we can import dispatcher and project_registry directly
_IDA_MCP_DIR = pathlib.Path(__file__).resolve().parents[1] / "src" / "ida_pro_mcp" / "ida_mcp"
sys.path.insert(0, str(_IDA_MCP_DIR))
try:
    from dispatcher import Dispatcher, DISPATCHER_PORT
    from project_registry import register_project, unregister_project
finally:
    sys.path.remove(str(_IDA_MCP_DIR))


class MockWorkerHandler(http.server.BaseHTTPRequestHandler):
    """Mock MCP worker that responds to tools/call and tools/list."""

    def log_message(self, format, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length))
        method = body.get("method", "")
        req_id = body.get("id", 1)

        if method == "tools/list":
            result = {
                "tools": [
                    {"name": "decompile", "description": "Decompile function"},
                    {"name": "list_funcs", "description": "List functions"},
                ]
            }
        elif method == "tools/call":
            params = body.get("params", {})
            tool_name = params.get("name", "")
            result = {
                "content": [{"type": "text", "text": f"mock:{tool_name}"}],
                "isError": False,
            }
        else:
            result = {"error": "unknown method"}

        response = json.dumps({"jsonrpc": "2.0", "id": req_id, "result": result}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)


@pytest.fixture
def tmp_config(tmp_path, monkeypatch):
    """Redirect config dir to a temp directory."""
    monkeypatch.setattr("project_registry.get_config_dir", lambda: str(tmp_path))
    return tmp_path


@pytest.fixture
def mock_worker(tmp_config):
    """Start a mock MCP worker on a random port."""
    import socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    server = http.server.HTTPServer(("127.0.0.1", port), MockWorkerHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    register_project("mock_project", port)

    yield port

    unregister_project(port)
    server.shutdown()


def test_dispatcher_has_local_tools():
    d = Dispatcher("127.0.0.1")
    assert "idb_list" in d.server.tools.methods
    assert "idb_select" in d.server.tools.methods
    assert "idb_current" in d.server.tools.methods


def test_idb_list_empty(tmp_config):
    d = Dispatcher("127.0.0.1")
    result = d.server.tools.methods["idb_list"]()
    assert result["projects"] == []


def test_idb_list_with_worker(tmp_config, mock_worker):
    d = Dispatcher("127.0.0.1")
    result = d.server.tools.methods["idb_list"]()
    assert len(result["projects"]) == 1
    assert result["projects"][0]["name"] == "mock_project"
    assert result["projects"][0]["port"] == mock_worker


def test_idb_select_no_projects(tmp_config):
    d = Dispatcher("127.0.0.1")
    result = d.server.tools.methods["idb_select"]("anything")
    assert "error" in result


def test_idb_select_by_port(tmp_config, mock_worker):
    d = Dispatcher("127.0.0.1")
    result = d.server.tools.methods["idb_select"](str(mock_worker))
    assert result["status"] == "ok"
    assert result["port"] == mock_worker


def test_idb_select_by_name(tmp_config, mock_worker):
    d = Dispatcher("127.0.0.1")
    result = d.server.tools.methods["idb_select"]("mock_project")
    assert result["status"] == "ok"
    assert result["target"] == "mock_project"


def test_idb_select_not_found(tmp_config, mock_worker):
    d = Dispatcher("127.0.0.1")
    result = d.server.tools.methods["idb_select"]("nonexistent")
    assert "error" in result
    assert "available" in result


def test_idb_current_no_target(tmp_config):
    d = Dispatcher("127.0.0.1")
    d._session_targets = {}
    result = d.server.tools.methods["idb_current"]()
    assert result["target_port"] is None


def test_idb_current_with_target(tmp_config, mock_worker):
    d = Dispatcher("127.0.0.1")
    d._session_targets[d._session_id()] = mock_worker
    result = d.server.tools.methods["idb_current"]()
    assert result["target_port"] == mock_worker
    assert result["target_project"] == "mock_project"


def test_auto_connect(tmp_config, mock_worker):
    d = Dispatcher("127.0.0.1")
    d._session_targets = {}
    port = d._get_target_port("new_session")
    assert port == mock_worker


def test_forward_to_worker(tmp_config, mock_worker):
    d = Dispatcher("127.0.0.1")
    result = d._forward_to_worker(mock_worker, "decompile", {"addr": "0x1000"})
    assert result is not None
    assert result.get("isError") is False
    content = result.get("content", [])
    assert any("mock:decompile" in c.get("text", "") for c in content)


def test_fetch_worker_tools(tmp_config, mock_worker):
    d = Dispatcher("127.0.0.1")
    tools = d._fetch_worker_tools(mock_worker)
    assert len(tools) == 2
    names = {t["name"] for t in tools}
    assert names == {"decompile", "list_funcs"}


def test_forward_no_worker(tmp_config):
    d = Dispatcher("127.0.0.1")
    d._session_targets = {}
    # Patched tools/call should return error when no worker available
    result = d.server.registry.methods["tools/call"]("decompile", {"addr": "0x1000"})
    assert result.get("isError") is True


def test_patches_installed():
    d = Dispatcher("127.0.0.1")
    assert "tools/list" in d.server.registry.methods
    assert "tools/call" in d.server.registry.methods
