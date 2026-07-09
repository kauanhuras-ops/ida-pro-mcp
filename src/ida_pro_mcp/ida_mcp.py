"""IDA Pro MCP Plugin Loader

This file serves as the entry point for IDA Pro's plugin system.
It loads the actual implementation from the ida_mcp package.
"""

import sys
import threading
import idaapi
import ida_kernwin
import ida_netnode
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from . import ida_mcp


def _get_plugin_version() -> str:
    """Best-effort version string for the running plugin (cached)."""
    try:
        if TYPE_CHECKING:
            from .ida_mcp.utils import get_server_version
        else:
            from ida_mcp.utils import get_server_version
        return get_server_version()
    except Exception:
        return "unknown"


NETNODE_AUTOSTART = "$ ida_mcp.autostart"
NETNODE_CONFIG = "$ ida_mcp.config"
_ALT_PORT = 0  # altval index for the persisted port (0 = not set)
_ALT_PERSIST = 1  # altval index for the "save host/port" preference
_SUP_HOST = 0  # supval index for the persisted host

_PLUGIN_VERSION = _get_plugin_version()


def _get_autostart() -> bool:
    """Read the autostart preference from the IDB. Defaults to True."""
    node = ida_netnode.netnode(NETNODE_AUTOSTART)
    val = node.altval(0)  # 0 = not set, 1 = off, 2 = on
    return val != 1


def _set_autostart(enabled: bool):
    """Persist the autostart preference into the IDB."""
    node = ida_netnode.netnode(NETNODE_AUTOSTART, 0, True)
    node.altset(0, 1 if not enabled else 2)


def _get_port(default: int) -> int:
    """Read the persisted server port from the IDB. Defaults to `default`."""
    node = ida_netnode.netnode(NETNODE_CONFIG)
    val = node.altval(_ALT_PORT)  # 0 = not set
    return val if val != 0 else default


def _set_port(port: int):
    """Persist the server port into the IDB."""
    node = ida_netnode.netnode(NETNODE_CONFIG, 0, True)
    node.altset(_ALT_PORT, port)


def _get_host(default: str) -> str:
    """Read the persisted server host from the IDB. Defaults to `default`."""
    node = ida_netnode.netnode(NETNODE_CONFIG)
    val = node.supstr(_SUP_HOST)
    return val if val else default


def _set_host(host: str):
    """Persist the server host into the IDB."""
    node = ida_netnode.netnode(NETNODE_CONFIG, 0, True)
    node.supset(_SUP_HOST, host)


def _get_persist() -> bool:
    """Read the 'save host/port' preference from the IDB. Defaults to True."""
    node = ida_netnode.netnode(NETNODE_CONFIG)
    val = node.altval(_ALT_PERSIST)  # 0 = not set, 1 = off, 2 = on
    return val != 1


def _set_persist(enabled: bool):
    """Persist the 'save host/port' preference into the IDB."""
    node = ida_netnode.netnode(NETNODE_CONFIG, 0, True)
    node.altset(_ALT_PERSIST, 2 if enabled else 1)


def _clear_endpoint():
    """Forget any persisted host/port so the next load uses the defaults."""
    node = ida_netnode.netnode(NETNODE_CONFIG, 0, True)
    node.altdel(_ALT_PORT)
    node.supdel(_SUP_HOST)


def unload_package(package_name: str):
    """Remove every module that belongs to the package from sys.modules."""
    to_remove = [
        mod_name
        for mod_name in sys.modules
        if mod_name == package_name or mod_name.startswith(package_name + ".")
    ]
    for mod_name in to_remove:
        del sys.modules[mod_name]


CONFIG_ACTION_ID = "mcp:configure"
CONFIG_ACTION_LABEL = "MCP Configuration"


class MCPConfigForm(idaapi.Form):
    """Form to configure MCP server."""

    def __init__(self, host: str, autostart: bool):
        form_str = r"""STARTITEM 0
MCP Server Configuration

Dispatcher port: 13337 (fixed)
<Host:{host}>
<Autostart server when IDA opens:{autostart}>{checks}>
"""
        super().__init__(
            form_str,
            {
                "host": idaapi.Form.StringInput(value=host),
                "checks": idaapi.Form.ChkGroupControl(
                    ("autostart",),
                    value=1 if autostart else 0,
                ),
            },
        )


class MCPConfigHandler(idaapi.action_handler_t):
    def __init__(self, plugin: "MCP"):
        idaapi.action_handler_t.__init__(self)
        self.plugin = plugin

    def activate(self, ctx):
        old_host = self.plugin.host
        old_autostart = self.plugin.autostart

        form = MCPConfigForm(self.plugin.host, self.plugin.autostart)
        form.Compile()
        ok = form.Execute()
        if ok != 1:
            form.Free()
            return 0

        host = form.host.value
        autostart = bool(form.checks.value & 1)
        form.Free()

        host_changed = host != old_host

        if autostart != old_autostart:
            self.plugin.autostart = autostart
            _set_autostart(autostart)
            print(f"[MCP] Autostart {'enabled' if autostart else 'disabled'}")

        if host_changed:
            self.plugin.host = host
            _set_host(host)
            print(f"[MCP] Host updated: {host}")

        if not host_changed and autostart == old_autostart:
            print(f"[MCP] Configuration unchanged: {host}")
            return 1

        # Apply new host immediately if the server is running.
        if host_changed and self.plugin.mcp is not None:
            print("[MCP] Applying configuration change without manual restart...")
            self.plugin.run(0)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class MCPUIHooks(ida_kernwin.UI_Hooks):
    """Defers menu attachment and autostart until the UI is fully ready."""

    def __init__(self, plugin: "MCP"):
        super().__init__()
        self.plugin = plugin

    def ready_to_run(self):
        ida_kernwin.attach_action_to_menu(
            "Edit/Plugins/", CONFIG_ACTION_ID, idaapi.SETMENU_APP
        )
        # Skip autostart when running under idalib – the idalib_server manages
        # the MCP server lifecycle itself and would otherwise hit a port conflict
        # because unload_package creates a separate MCP_SERVER instance.
        if self.plugin.autostart and ida_kernwin.is_idaq():
            print(f"[MCP] Autostarting server (v{_PLUGIN_VERSION})...")
            self.plugin.run(0)
        self.unhook()


class MCP(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "MCP Plugin"
    help = "MCP"
    wanted_name = "MCP"
    wanted_hotkey = "Ctrl-Alt-M"

    DEFAULT_HOST = "127.0.0.1"
    DEFAULT_PORT = 13337  # dispatcher port

    def init(self):
        hotkey = MCP.wanted_hotkey.replace("-", "+")
        if __import__("sys").platform == "darwin":
            hotkey = hotkey.replace("Alt", "Option")

        self.mcp: "ida_mcp.rpc.McpServer | None" = None
        self.dispatcher = None  # Dispatcher instance if this is the dispatcher
        self._promotion_stop = threading.Event()
        self._promotion_thread: threading.Thread | None = None
        self._registered_project_port: int | None = None
        self.autostart = _get_autostart()
        self.persist_endpoint = _get_persist()
        self.host = self.DEFAULT_HOST
        # Always use DEFAULT_PORT (13337) for dispatcher logic.
        # Persisted port is ignored — the architecture requires 13337 = dispatcher.
        self.port = self.DEFAULT_PORT

        if self.autostart and ida_kernwin.is_idaq():
            print(f"[MCP] v{_PLUGIN_VERSION} loaded, server will start automatically")
        elif not ida_kernwin.is_idaq():
            print(f"[MCP] v{_PLUGIN_VERSION} loaded (idalib mode, server managed externally)")
        else:
            print(
                f"[MCP] v{_PLUGIN_VERSION} loaded, use Edit -> Plugins -> MCP ({hotkey}) to start the server"
            )

        # Register a separate menu item for host/port configuration
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                CONFIG_ACTION_ID,
                CONFIG_ACTION_LABEL,
                MCPConfigHandler(self),
            )
        )
        # Defer menu attachment and autostart until the UI is fully initialized
        self._ui_hooks = MCPUIHooks(self)
        self._ui_hooks.hook()

        return idaapi.PLUGIN_KEEP

    def _get_project_name(self) -> str:
        """Get the current IDB project name."""
        try:
            import ida_nalt
            import os
            binary = ida_nalt.get_root_filename() or ""
            if binary:
                return os.path.splitext(os.path.basename(binary))[0]
        except Exception:
            pass
        return "unknown"

    def _get_idb_path(self) -> str:
        try:
            import idc
            return idc.get_idb_path() or ""
        except Exception:
            return ""

    def _unregister_instance(self):
        port = getattr(self, "_registered_port", None)
        if port is not None:
            try:
                if TYPE_CHECKING:
                    from .ida_mcp.discovery import unregister_instance
                else:
                    from ida_mcp.discovery import unregister_instance
                unregister_instance(port)
            except Exception as e:
                print(f"[MCP] Instance unregistration failed: {e}")
            self._registered_port = None

    def _unregister_project(self):
        port = getattr(self, "_registered_project_port", None)
        if port is not None:
            try:
                if TYPE_CHECKING:
                    from .ida_mcp.project_registry import unregister_project
                else:
                    from ida_mcp.project_registry import unregister_project
                unregister_project(port)
            except Exception as e:
                print(f"[MCP] Project unregistration failed: {e}")
            self._registered_project_port = None

    def run(self, arg):
        # Stop everything
        self._stop_promotion()
        if self.dispatcher:
            self.dispatcher.stop()
            self.dispatcher = None
        if self.mcp:
            self._unregister_instance()
            self._unregister_project()
            self.mcp.stop()
            self.mcp = None

        # HACK: ensure fresh load of ida_mcp package
        unload_package("ida_mcp")

        # Try to become dispatcher on DEFAULT_PORT (13337)
        try:
            if TYPE_CHECKING:
                from .ida_mcp.dispatcher import Dispatcher
            else:
                from ida_mcp.dispatcher import Dispatcher

            self.dispatcher = Dispatcher(self.host, self._get_idb_path())
            if self.dispatcher.start():
                print(f"[MCP] v{_PLUGIN_VERSION} dispatcher on http://{self.host}:{self.DEFAULT_PORT}")
                # Start own worker on next port
                self._start_worker(self.DEFAULT_PORT + 1)
                self._start_promotion()
                return
            else:
                self.dispatcher = None
        except Exception as e:
            print(f"[MCP] Dispatcher start failed: {e}")
            self.dispatcher = None

        # Port 13337 occupied — start as worker
        self._start_worker(self.DEFAULT_PORT + 1)
        self._start_promotion()

    def _start_worker(self, start_port: int):
        """Start the worker MCP server starting from start_port."""
        if TYPE_CHECKING:
            from .ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler
        else:
            from ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler

        port = start_port
        max_port = self.DEFAULT_PORT + 100
        while port < max_port:
            try:
                MCP_SERVER.serve(
                    self.host, port, request_handler=IdaMcpHttpRequestHandler
                )
                role = "dispatcher-worker" if self.dispatcher else "worker"
                print(f"[MCP] v{_PLUGIN_VERSION} {role} on http://{self.host}:{port}")
                print(f"  Config: http://{self.host}:{port}/config.html")
                self.mcp = MCP_SERVER
                self._register_instance(port)
                # Register in project registry
                try:
                    if TYPE_CHECKING:
                        from .ida_mcp.project_registry import register_project
                    else:
                        from ida_mcp.project_registry import register_project
                    project_name = self._get_project_name()
                    file_path = register_project(project_name, port)
                    self._registered_project_port = port
                    print(f"[MCP] Registered project: {project_name} (:{port})")
                    print(f"  Project file: {file_path}")
                except Exception as e:
                    print(f"[MCP] Project registration failed: {e}")
                return
            except OSError as e:
                if e.errno in (48, 98, 10048):  # Address already in use
                    port += 1
                else:
                    raise
        print(f"[MCP] Error: No available port in range {start_port}-{max_port - 1}")

    def _start_promotion(self):
        """Start background thread that tries to claim dispatcher port."""
        self._promotion_stop.clear()
        self._promotion_thread = threading.Thread(
            target=self._promotion_loop, daemon=True, name="mcp-promotion"
        )
        self._promotion_thread.start()

    def _stop_promotion(self):
        self._promotion_stop.set()
        if self._promotion_thread:
            self._promotion_thread.join(timeout=7)
            self._promotion_thread = None

    def _promotion_loop(self):
        """Every 5s, try to bind dispatcher port. If successful, promote."""
        import socket
        while not self._promotion_stop.is_set():
            self._promotion_stop.wait(5)
            if self._promotion_stop.is_set():
                break
            if self.dispatcher is not None:
                continue  # Already dispatcher
            # Try to bind dispatcher port
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind((self.host, self.DEFAULT_PORT))
                sock.close()
            except OSError:
                continue  # Port still occupied
            # Port is free — promote
            print("[MCP] Dispatcher port free, promoting to dispatcher...", flush=True)
            try:
                if TYPE_CHECKING:
                    from .ida_mcp.dispatcher import Dispatcher
                else:
                    from ida_mcp.dispatcher import Dispatcher

                # Stop current worker
                if self.mcp:
                    self._unregister_instance()
                    self._unregister_project()
                    self.mcp.stop()
                    self.mcp = None

                # Start dispatcher
                self.dispatcher = Dispatcher(self.host, self._get_idb_path())
                if self.dispatcher.start():
                    print(f"[MCP] Promoted to dispatcher on http://{self.host}:{self.DEFAULT_PORT}")
                    # Restart worker
                    self._start_worker(self.DEFAULT_PORT + 1)
                else:
                    print("[MCP] Dispatcher bind failed, staying as worker")
                    self.dispatcher = None
                    # Restart worker on same port
                    self._start_worker(self.DEFAULT_PORT + 1)
            except Exception as e:
                print(f"[MCP] Promotion failed: {e}")
                self.dispatcher = None
                self._start_worker(self.DEFAULT_PORT + 1)

    def _register_instance(self, port: int):
        try:
            if TYPE_CHECKING:
                from .ida_mcp.discovery import register_instance
            else:
                from ida_mcp.discovery import register_instance
            import os
            binary = ""
            idb_path = self._get_idb_path()
            try:
                import ida_nalt
                binary = ida_nalt.get_root_filename() or ""
            except Exception:
                pass
            file_path = register_instance(
                host=self.host,
                port=port,
                pid=os.getpid(),
                binary=binary,
                idb_path=idb_path,
            )
            self._registered_port = port
            print(f"[MCP] Registered instance: {binary} (pid={os.getpid()}, port={port})")
            print(f"  Discovery file: {file_path}")
        except Exception as e:
            import traceback
            print(f"[MCP] Instance unregistration failed: {e}")
            traceback.print_exc()

    def term(self):
        if hasattr(self, "_ui_hooks"):
            self._ui_hooks.unhook()
        ida_kernwin.unregister_action(CONFIG_ACTION_ID)
        self._stop_promotion()
        if self.dispatcher:
            self.dispatcher.stop()
            self.dispatcher = None
        self._unregister_project()
        self._unregister_instance()
        if self.mcp:
            self.mcp.stop()


def PLUGIN_ENTRY():
    return MCP()


