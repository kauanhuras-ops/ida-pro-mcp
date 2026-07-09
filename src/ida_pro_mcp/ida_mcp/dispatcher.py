"""Dispatcher MCP server for IDA MCP routing.

Runs on port 13337. Routes MCP clients to IDA workers via sticky sessions.
Clients call idb_list to see projects, idb_select to switch, and all other
tool calls are forwarded to the targeted worker.
"""

import http.client
import json
import os
import sys
import threading
import time
from typing import Optional

# Lazy imports to allow direct import outside IDA for testing.
_project_registry = None
_McpServer = None


def _ensure_imports():
    global _project_registry, _McpServer
    if _project_registry is None:
        # Import project_registry — works both as package submodule and standalone
        _ida_mcp_dir = os.path.dirname(os.path.abspath(__file__))
        if _ida_mcp_dir not in sys.path:
            sys.path.insert(0, _ida_mcp_dir)
        try:
            import project_registry as _pr
            _project_registry = _pr
        finally:
            if _ida_mcp_dir in sys.path:
                sys.path.remove(_ida_mcp_dir)
    if _McpServer is None:
        # Try relative import first (when loaded as ida_mcp.dispatcher),
        # fall back to sys.path approach (when loaded directly).
        try:
            from .zeromcp import McpServer as _MS
        except ImportError:
            _ida_mcp_dir = os.path.dirname(os.path.abspath(__file__))
            if _ida_mcp_dir not in sys.path:
                sys.path.insert(0, _ida_mcp_dir)
            try:
                from zeromcp import McpServer as _MS
            finally:
                if _ida_mcp_dir in sys.path:
                    sys.path.remove(_ida_mcp_dir)
        _McpServer = _MS


def _list_projects():
    _ensure_imports()
    return _project_registry.list_projects()


def _cleanup_stale_projects():
    _ensure_imports()
    return _project_registry.cleanup_stale_projects()


DISPATCHER_PORT = 13337


class Dispatcher:
    """MCP server that routes clients to IDA workers."""

    def __init__(self, host: str, idb_path: str = ""):
        _ensure_imports()
        self.host = host
        self.port = DISPATCHER_PORT
        self.idb_path = idb_path
        self.server = _McpServer("ida-mcp-dispatcher")
        self._session_targets: dict[str, int] = {}  # session_id -> worker port
        self._cleanup_stop = threading.Event()
        self._cleanup_thread: threading.Thread | None = None
        self._install_local_tools()
        self._install_patches()

    # ------------------------------------------------------------------
    # Session helpers
    # ------------------------------------------------------------------

    def _session_id(self) -> str:
        sid = self.server.get_current_transport_session_id()
        return sid or "stdio:default"

    def _get_target_port(self, session_id: str | None = None) -> int | None:
        sid = session_id or self._session_id()
        if sid in self._session_targets:
            return self._session_targets[sid]
        # Auto-connect to first available worker
        projects = _list_projects()
        if projects:
            self._session_targets[sid] = projects[0].port
            return projects[0].port
        return None

    # ------------------------------------------------------------------
    # Forwarding
    # ------------------------------------------------------------------

    def _forward_to_worker(
        self, port: int, tool_name: str, arguments: dict | None
    ) -> dict | None:
        """Forward a tool call to a worker via HTTP."""
        try:
            payload = json.dumps({
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": arguments or {}},
                "id": 1,
            }).encode()
            conn = http.client.HTTPConnection(self.host, port, timeout=60)
            conn.request("POST", "/mcp", payload, {"Content-Type": "application/json"})
            resp = conn.getresponse()
            raw = resp.read().decode()
            conn.close()
            data = json.loads(raw)
            # Extract from JSON-RPC envelope
            if isinstance(data, dict) and "result" in data:
                result = data["result"]
                if isinstance(result, dict) and "content" in result:
                    return result
            return data
        except Exception as e:
            return {
                "content": [{"type": "text", "text": f"Worker {tool_name} error: {e}"}],
                "isError": True,
            }

    def _fetch_worker_tools(self, port: int) -> list[dict]:
        """Fetch tools/list from a worker."""
        try:
            payload = json.dumps({
                "jsonrpc": "2.0",
                "method": "tools/list",
                "params": {},
                "id": 1,
            }).encode()
            conn = http.client.HTTPConnection(self.host, port, timeout=5)
            conn.request("POST", "/mcp", payload, {"Content-Type": "application/json"})
            resp = conn.getresponse()
            raw = resp.read().decode()
            conn.close()
            data = json.loads(raw)
            if isinstance(data, dict) and "result" in data:
                result = data["result"]
                if isinstance(result, dict) and "tools" in result:
                    return result["tools"]
            return []
        except Exception:
            return []

    # ------------------------------------------------------------------
    # Local tools (run on dispatcher, never forwarded)
    # ------------------------------------------------------------------

    _LOCAL_TOOLS = frozenset({"idb_list", "idb_select", "idb_current"})

    def _install_local_tools(self) -> None:
        @self.server.tool
        def idb_list() -> dict:
            """List all running IDA projects.

            Returns the list of projects with their ports and status.
            Use idb_select to switch the current session to a project.
            """
            projects = _list_projects()
            current_port = self._get_target_port()
            result = []
            for p in projects:
                result.append({
                    "name": p.name,
                    "port": p.port,
                    "is_current": p.port == current_port,
                })
            return {
                "projects": result,
                "target_port": current_port,
                "session_id": self._session_id(),
            }

        @self.server.tool
        def idb_select(target: str) -> dict:
            """Switch the current session to a different IDA project.

            Args:
                target: Project name or port number to connect to.
            """
            projects = _list_projects()
            if not projects:
                return {"error": "No projects available"}

            # Match by port number
            try:
                target_port = int(target)
                for p in projects:
                    if p.port == target_port:
                        self._session_targets[self._session_id()] = p.port
                        return {
                            "status": "ok",
                            "target": p.name,
                            "port": p.port,
                        }
            except ValueError:
                pass

            # Match by name
            for p in projects:
                if p.name == target:
                    self._session_targets[self._session_id()] = p.port
                    return {
                        "status": "ok",
                        "target": p.name,
                        "port": p.port,
                    }

            available = [f"{p.name} (:{p.port})" for p in projects]
            return {
                "error": f"Project '{target}' not found",
                "available": available,
            }

        @self.server.tool
        def idb_current() -> dict:
            """Show the current session's routing target."""
            sid = self._session_id()
            port = self._get_target_port(sid)
            name = None
            if port:
                for p in _list_projects():
                    if p.port == port:
                        name = p.name
                        break
            return {
                "session_id": sid,
                "target_project": name,
                "target_port": port,
            }

    # ------------------------------------------------------------------
    # Patches: tools/list merge + tools/call forwarding
    # ------------------------------------------------------------------

    def _install_patches(self) -> None:
        # Patch tools/call
        original_call = self.server.registry.methods["tools/call"]

        def patched_call(
            name: str, arguments: Optional[dict] = None, _meta: Optional[dict] = None
        ) -> dict:
            if name in self._LOCAL_TOOLS:
                return original_call(name, arguments, _meta)
            port = self._get_target_port()
            if port is not None:
                remote = self._forward_to_worker(port, name, arguments)
                if remote is not None:
                    return remote
            return {
                "content": [{"type": "text", "text": "No IDA project available"}],
                "isError": True,
            }

        self.server.registry.methods["tools/call"] = patched_call

        # Patch tools/list
        original_list = self.server.registry.methods["tools/list"]

        def patched_list(_meta: Optional[dict] = None) -> dict:
            local_result = original_list(_meta)
            local_tools = local_result.get("tools", [])
            local_names = {t.get("name") for t in local_tools if isinstance(t, dict)}

            port = self._get_target_port()
            if port is not None:
                remote_tools = self._fetch_worker_tools(port)
                for tool_def in remote_tools:
                    if isinstance(tool_def, dict) and tool_def.get("name") not in local_names:
                        local_tools.append(tool_def)

            return {"tools": local_tools}

        self.server.registry.methods["tools/list"] = patched_list

    # ------------------------------------------------------------------
    # Cleanup thread
    # ------------------------------------------------------------------

    def _cleanup_loop(self) -> None:
        while not self._cleanup_stop.is_set():
            self._cleanup_stop.wait(10)
            if self._cleanup_stop.is_set():
                break
            removed = _cleanup_stale_projects()
            if removed:
                for entry in removed:
                    print(
                        f"[MCP-dispatcher] Removed stale project: "
                        f"{entry.name} (:{entry.port})",
                        flush=True,
                    )
                # Clean up session targets pointing to removed ports
                dead_ports = {e.port for e in removed}
                dead_sessions = [
                    sid for sid, port in self._session_targets.items()
                    if port in dead_ports
                ]
                for sid in dead_sessions:
                    del self._session_targets[sid]

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> bool:
        """Start the dispatcher on port 13337. Returns True if started."""
        try:
            self.server.serve(self.host, self.port)
        except OSError:
            return False
        print(f"[MCP-dispatcher] Listening on http://{self.host}:{self.port}", flush=True)
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop, daemon=True, name="mcp-dispatcher-cleanup"
        )
        self._cleanup_thread.start()
        return True

    def stop(self) -> None:
        """Stop the dispatcher."""
        self._cleanup_stop.set()
        if self._cleanup_thread:
            self._cleanup_thread.join(timeout=3)
            self._cleanup_thread = None
        self.server.stop()
