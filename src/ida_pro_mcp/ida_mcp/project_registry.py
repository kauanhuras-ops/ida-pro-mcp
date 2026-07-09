"""Project registry for IDA MCP dispatcher.

Workers register themselves by creating empty files in ~/.ida-mcp/:
    project_name.port   (e.g. road_rash.13339)

The dispatcher uses these files to discover available workers.
"""

import glob
import os
import socket
from dataclasses import dataclass


@dataclass
class ProjectEntry:
    name: str
    port: int
    file_path: str


def get_config_dir() -> str:
    return os.path.join(os.path.expanduser("~"), ".ida-mcp")


def _parse_project_file(file_path: str) -> ProjectEntry | None:
    basename = os.path.basename(file_path)
    # Format: project_name.port
    parts = basename.rsplit(".", 1)
    if len(parts) != 2:
        return None
    name, port_str = parts
    try:
        port = int(port_str)
    except ValueError:
        return None
    if not name or port < 1 or port > 65535:
        return None
    return ProjectEntry(name=name, port=port, file_path=file_path)


def register_project(project_name: str, port: int) -> str:
    """Create a project file. Returns the file path."""
    config_dir = get_config_dir()
    os.makedirs(config_dir, exist_ok=True)
    # Sanitize project name for filesystem
    safe_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in project_name)
    if not safe_name:
        safe_name = f"project_{port}"
    file_path = os.path.join(config_dir, f"{safe_name}.{port}")
    # Touch the file (empty)
    with open(file_path, "w") as f:
        pass
    return file_path


def unregister_project(port: int) -> bool:
    """Remove the project file for the given port. Returns True if removed."""
    config_dir = get_config_dir()
    if not os.path.isdir(config_dir):
        return False
    for entry in list_projects():
        if entry.port == port:
            try:
                os.unlink(entry.file_path)
                return True
            except OSError:
                return False
    return False


def list_projects() -> list[ProjectEntry]:
    """List all registered project files."""
    config_dir = get_config_dir()
    if not os.path.isdir(config_dir):
        return []
    result = []
    for path in glob.glob(os.path.join(config_dir, "*.*")):
        if os.path.isfile(path) and not os.path.basename(path).startswith("."):
            entry = _parse_project_file(path)
            if entry:
                result.append(entry)
    result.sort(key=lambda e: e.name)
    return result


def _is_port_alive(port: int, host: str = "127.0.0.1", timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


def cleanup_stale_projects() -> list[ProjectEntry]:
    """Remove project files for dead ports. Returns removed entries."""
    removed = []
    for entry in list_projects():
        if not _is_port_alive(entry.port):
            try:
                os.unlink(entry.file_path)
                removed.append(entry)
            except OSError:
                pass
    return removed


def find_project(name: str) -> ProjectEntry | None:
    """Find a project by name."""
    for entry in list_projects():
        if entry.name == name:
            return entry
    return None
