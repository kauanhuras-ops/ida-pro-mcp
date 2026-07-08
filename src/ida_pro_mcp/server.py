import argparse
import http.client
import json
import os
import re
import sys
import threading
import time
import traceback
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlparse

if TYPE_CHECKING:
    from ida_pro_mcp.ida_mcp.zeromcp import (
        EXTERNAL_BASE_HEADER,
        McpHttpRequestHandler,
        McpServer,
        get_current_request_external_base_url,
    )
    from ida_pro_mcp.ida_mcp.zeromcp.jsonrpc import JsonRpcRequest, JsonRpcResponse
else:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "ida_mcp"))
    from zeromcp import (
        EXTERNAL_BASE_HEADER,
        McpHttpRequestHandler,
        McpServer,
        get_current_request_external_base_url,
    )
    from zeromcp.jsonrpc import JsonRpcRequest, JsonRpcResponse

    sys.path.pop(0)

try:
    from .installer import (
        list_available_clients,
        print_mcp_config,
        run_install_command,
        set_ida_rpc,
    )
except ImportError:
    from installer import (
        list_available_clients,
        print_mcp_config,
        run_install_command,
        set_ida_rpc,
    )

try:
    from .ida_mcp.discovery import discover_instances, probe_instance
except ImportError:
    try:
        from ida_mcp.discovery import discover_instances, probe_instance
    except ImportError:
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "ida_mcp"))
        from discovery import discover_instances, probe_instance

        sys.path.pop(0)

try:
    from .routing import (
        SessionTargets,
        list_instances_to_response,
        forward_json_rpc,
        select_target,
    )
except ImportError:
    from routing import (  # type: ignore[no-redef]
        SessionTargets,
        list_instances_to_response,
        forward_json_rpc,
        select_target,
    )

DEFAULT_IDA_HOST = "127.0.0.1"
DEFAULT_IDA_PORT = 13337
IDA_HOST = DEFAULT_IDA_HOST
IDA_PORT = DEFAULT_IDA_PORT

mcp = McpServer("ida-pro-mcp")
dispatch_original = mcp.registry.dispatch

# Per-MCP-session routing state. Each MCP transport session (HTTP Mcp-Session-Id
# or "stdio:default") picks a target IDA via idb_select. While a session has a
# target, every tools/call from it is forwarded to that IDA. Concurrent
# sessions stay isolated: project A for one client, project B for another.
_SESSION_TARGETS = SessionTargets()

# Tools the proxy handles locally instead of forwarding to the IDA.
_PROXY_LOCAL_TOOLS = frozenset({"idb_list", "idb_select"})

_OUTPUT_PATH_RE = re.compile(r"^/output/([a-f0-9-]+)\.(\w+)$")


def _get_proxy_request_path() -> str:
    """Build the proxied MCP path, preserving enabled extensions."""
    enabled = sorted(getattr(mcp._enabled_extensions, "data", set()))
    if enabled:
        return f"/mcp?ext={','.join(enabled)}"
    return "/mcp"


def _get_proxy_request_headers() -> dict[str, str]:
    """Build proxy request headers, preserving HTTP MCP session identity."""
    headers = {"Content-Type": "application/json"}
    transport_session_id = mcp.get_current_transport_session_id()
    if transport_session_id and transport_session_id.startswith("http:"):
        session_id = transport_session_id.split(":", 1)[1]
        if session_id and session_id != "anonymous":
            headers["Mcp-Session-Id"] = session_id
    external_base_url = get_current_request_external_base_url()
    if external_base_url:
        headers[EXTERNAL_BASE_HEADER] = external_base_url
    return headers


def _proxy_to_ida(payload: bytes | str | dict, host: str, port: int) -> dict:
    """Forward a JSON-RPC request to ``host:port`` and return the response.

    If the connection is refused (IDA was closed/restarting) we poll the port
    for up to RECOVERY_TIMEOUT_SEC before giving up. Other errors propagate
    immediately — the dispatcher's error envelope will surface them to the
    caller. Mutating operations are NOT silently retried: the caller can see
    whether the request reached the IDA before deciding to retry.
    """
    return forward_json_rpc(
        payload,
        host=host,
        port=port,
        path=_get_proxy_request_path(),
        headers=_get_proxy_request_headers(),
    )


def _proxy_output_download(path: str, host: str, port: int) -> tuple[int, str, list[tuple[str, str]], bytes]:
    """Proxy a raw output download from ``host:port``."""
    conn = http.client.HTTPConnection(host, port, timeout=30)
    try:
        conn.request("GET", path)
        response = conn.getresponse()
        return response.status, response.reason, response.getheaders(), response.read()
    finally:
        conn.close()


# ============================================================================
# Per-session routing
# ============================================================================


def _current_proxy_session_id() -> str:
    """Session key for the current request. Stdio clients share ``stdio:default``;
    HTTP clients are keyed on ``Mcp-Session-Id`` (or ``http:anonymous``)."""
    return mcp.get_current_transport_session_id() or "stdio:default"


def _resolve_session_target() -> tuple[str, int, str]:
    """Pick (host, port, idb_path) for the current request.

    Priority:
      1. Per-session target chosen via idb_select.
      2. Global IDA_HOST / IDA_PORT set by --ida-rpc or startup discovery.
         ``idb_path`` is unknown in this case — empty string.
    """
    target = _SESSION_TARGETS.get(_current_proxy_session_id())
    if target is not None:
        return target
    return (IDA_HOST, IDA_PORT, "")


def _idb_list_impl() -> dict:
    """Return all known IDA instances, with the current session's target marked.

    Runs locally in the proxy — does not forward to any single IDA, so the
    agent sees every project it's allowed to attach to, not just the one
    the proxy happened to auto-pick.
    """
    return list_instances_to_response(
        discover_instances(),
        current=_resolve_session_target(),
    )


def _idb_select_impl(target: str) -> dict:
    """Pin the current session to one IDA by ``idb_path`` (preferred) or ``port``.

    Each MCP session keeps its own target — concurrent sessions can attach to
    different IDAs. Once selected, every ``tools/call`` from this session is
    forwarded to that IDA. If the IDA goes down, the proxy polls its port
    for up to 30 s before reporting the failure.
    """
    sid = _current_proxy_session_id()

    def set_target(host: str, port: int, idb_path: str) -> None:
        _SESSION_TARGETS.set(sid, host, port, idb_path)

    return select_target(target, discover_instances(), set_target=set_target)


def _register_proxy_local_tools() -> None:
    """Register ``idb_list`` / ``idb_select`` on the proxy's mcp registry.

    ``McpServer.tool`` attaches metadata so the names appear in ``tools/list``.
    The actual dispatch still flows through the registry's ``tools/call``
    handler — we rely on ``dispatch_proxy`` to detect these names and route
    them to the local handlers instead of forwarding to an IDA.
    """
    mcp.tool(_idb_list_impl)
    mcp.tool(_idb_select_impl)


_register_proxy_local_tools()


def dispatch_proxy(request: dict | str | bytes | bytearray) -> JsonRpcResponse | None:
    """Dispatch JSON-RPC requests.

    - ``initialize`` / notifications  → original handler (handled locally).
    - ``tools/call`` for ``idb_list`` / ``idb_select`` → local handlers.
    - everything else → forward to the current session's targeted IDA,
      waiting up to 30 s on connection-refused in case the IDA is restarting.
    """
    if not isinstance(request, dict):
        request_obj: JsonRpcRequest = json.loads(request)
    else:
        request_obj: JsonRpcRequest = request  # type: ignore

    if request_obj["method"] == "initialize":
        return dispatch_original(request)
    if request_obj["method"].startswith("notifications/"):
        return dispatch_original(request)

    if request_obj["method"] == "tools/call":
        params = request_obj.get("params") or {}
        tool_name = params.get("name") if isinstance(params, dict) else None
        if tool_name in _PROXY_LOCAL_TOOLS:
            return dispatch_original(request)

    host, port, idb_path = _resolve_session_target()
    try:
        return _proxy_to_ida(request, host, port)
    except Exception as e:
        full_info = traceback.format_exc()
        request_id = request_obj.get("id")
        if request_id is None:
            return None  # Notification, no response needed

        shortcut = "Ctrl+Option+M" if sys.platform == "darwin" else "Ctrl+Alt+M"
        location_hint = (
            f"the targeted IDA at {host}:{port}"
            + (f" ({idb_path})" if idb_path else "")
        )
        return JsonRpcResponse(
            {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32000,
                    "message": (
                        "Failed to complete request to IDA Pro. "
                        f"{location_hint}. "
                        f"Was the plugin (Edit -> Plugins -> MCP, {shortcut}) "
                        "loaded and the server started? If the IDA process "
                        "crashed, restart it; if it was never started, run "
                        "idb_list to verify availability before retrying. "
                        "This request was NOT retried silently — verify IDA "
                        "state before retrying mutating operations.\n"
                        f"{full_info}"
                    ),
                    "data": str(e),
                },
                "id": request_id,
            }
        )


mcp.registry.dispatch = dispatch_proxy


class ProxyHttpRequestHandler(McpHttpRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if _OUTPUT_PATH_RE.match(parsed.path):
            if not self._check_api_request():
                return
            host, port, _ = _resolve_session_target()
            try:
                status, _, response_headers, body = _proxy_output_download(parsed.path, host, port)
            except Exception as e:
                self.send_error(502, f"Failed to proxy output download: {e}")
                return

            self.send_response(status)
            for header, value in response_headers:
                if header.lower() == "transfer-encoding":
                    continue
                self.send_header(header, value)
            self.send_cors_headers()
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()


DEFAULT_IDA_RPC = f"http://{IDA_HOST}:{IDA_PORT}"


def _resolve_ida_rpc(args) -> None:
    """Resolve the IDA RPC target: explicit --ida-rpc, or auto-discovery."""
    global IDA_HOST, IDA_PORT

    if args.ida_rpc is not None:
        # Explicit --ida-rpc: use directly (backwards compatible)
        ida_rpc = urlparse(args.ida_rpc)
        if ida_rpc.hostname is None or ida_rpc.port is None:
            raise Exception(f"Invalid IDA RPC server: {args.ida_rpc}")
        IDA_HOST = ida_rpc.hostname
        IDA_PORT = ida_rpc.port

        # Preserve ?ext= query param so proxy requests include the extensions
        ext_value = parse_qs(ida_rpc.query).get("ext", [""])[0]
        if ext_value:
            mcp._enabled_extensions.data = set(ext_value.split(","))

        set_ida_rpc(IDA_HOST, IDA_PORT)
        return

    # Auto-discover running IDA instances
    instances = discover_instances()
    if len(instances) == 0:
        print(
            f"[MCP] No IDA instances discovered, using default {IDA_HOST}:{IDA_PORT}",
            file=sys.stderr,
        )
    elif len(instances) == 1:
        inst = instances[0]
        IDA_HOST = inst["host"]
        IDA_PORT = inst["port"]
        print(
            f"[MCP] Auto-connected to: {inst['binary']} at {IDA_HOST}:{IDA_PORT}",
            file=sys.stderr,
        )
    else:
        print(f"[MCP] Found {len(instances)} IDA instances:", file=sys.stderr)
        for i, inst in enumerate(instances):
            print(f"  [{i}] {inst['binary']} at {inst['host']}:{inst['port']}", file=sys.stderr)
        inst = instances[0]
        IDA_HOST = inst["host"]
        IDA_PORT = inst["port"]
        print(
            f"[MCP] Auto-selected: {inst['binary']}. "
            "Pass --ida-rpc http://host:port to override.",
            file=sys.stderr,
        )

    set_ida_rpc(IDA_HOST, IDA_PORT)


def main():
    global IDA_HOST, IDA_PORT

    parser = argparse.ArgumentParser(description="IDA Pro MCP Server")
    parser.add_argument(
        "--install",
        nargs="?",
        const="",
        default=None,
        metavar="TARGETS",
        help="Install the MCP Server and IDA plugin. "
        "The IDA plugin is installed immediately. "
        "Optionally specify comma-separated client targets (e.g., 'claude,cursor'). "
        "Without targets, an interactive selector is shown.",
    )
    parser.add_argument(
        "--uninstall",
        nargs="?",
        const="",
        default=None,
        metavar="TARGETS",
        help="Uninstall the MCP Server and IDA plugin. "
        "The IDA plugin is uninstalled immediately. "
        "Optionally specify comma-separated client targets. "
        "Without targets, an interactive selector is shown.",
    )
    parser.add_argument(
        "--allow-ida-free",
        action="store_true",
        help="Allow installation despite IDA Free being installed",
    )
    parser.add_argument(
        "--transport",
        type=str,
        default=None,
        help="MCP transport for install: 'streamable-http' (default), 'stdio', or 'sse'. "
        "For running: use stdio (default) or pass a URL (e.g., http://127.0.0.1:8744[/mcp|/sse])",
    )
    parser.add_argument(
        "--scope",
        type=str,
        choices=["global", "project"],
        default=None,
        help="Installation scope: 'project' (current directory, default) or 'global' (user-level)",
    )
    parser.add_argument(
        "--ida-rpc",
        type=str,
        default=None,
        help=f"IDA RPC server (default: auto-discover, fallback: {DEFAULT_IDA_RPC})",
    )
    parser.add_argument(
        "--config", action="store_true", help="Generate MCP config JSON"
    )
    parser.add_argument(
        "--list-clients",
        action="store_true",
        help="List all available MCP client targets",
    )
    args = parser.parse_args()

    # Handle --list-clients independently
    if args.list_clients:
        list_available_clients()
        return

    # Resolve IDA RPC target (explicit or auto-discovery)
    _resolve_ida_rpc(args)

    is_install = args.install is not None
    is_uninstall = args.uninstall is not None

    # Validate flag combinations
    if args.scope and not (is_install or is_uninstall):
        print("--scope requires --install or --uninstall")
        return

    if is_install and is_uninstall:
        print("Cannot install and uninstall at the same time")
        return

    if is_install or is_uninstall:
        run_install_command(
            uninstall=is_uninstall,
            targets_str=args.install if is_install else args.uninstall,
            args=args,
        )
        return

    if args.config:
        print_mcp_config()
        return

    try:
        transport = args.transport or "stdio"
        if transport == "stdio":
            mcp.stdio()
        else:
            url = urlparse(transport)
            if url.hostname is None or url.port is None:
                raise Exception(f"Invalid transport URL: {args.transport}")
            # NOTE: npx -y @modelcontextprotocol/inspector for debugging
            mcp.serve(url.hostname, url.port, request_handler=ProxyHttpRequestHandler)
            input("Server is running, press Enter or Ctrl+C to stop.")
    except (KeyboardInterrupt, EOFError):
        pass


if __name__ == "__main__":
    main()
