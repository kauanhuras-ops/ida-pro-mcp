"""Tests for ida_mcp.project_registry.

These run outside IDA: the module imports nothing IDA-specific.
"""

import pathlib
import sys
import os
import pytest

# Add ida_mcp to path so we can import project_registry directly
_IDA_MCP_SRC = pathlib.Path(__file__).resolve().parents[1] / "src" / "ida_pro_mcp" / "ida_mcp"
sys.path.insert(0, str(_IDA_MCP_SRC))
try:
    from project_registry import (
        ProjectEntry,
        _parse_project_file,
        get_config_dir,
        list_projects,
        register_project,
        unregister_project,
        find_project,
        cleanup_stale_projects,
    )
finally:
    sys.path.remove(str(_IDA_MCP_SRC))


@pytest.fixture
def tmp_config(tmp_path, monkeypatch):
    """Redirect config dir to a temp directory."""
    monkeypatch.setattr("project_registry.get_config_dir", lambda: str(tmp_path))
    return tmp_path


def test_parse_project_file_valid(tmp_path):
    f = tmp_path / "road_rash.13339"
    f.touch()
    entry = _parse_project_file(str(f))
    assert entry is not None
    assert entry.name == "road_rash"
    assert entry.port == 13339
    assert entry.file_path == str(f)


def test_parse_project_file_with_dots_in_name(tmp_path):
    f = tmp_path / "my.cool.project.13339"
    f.touch()
    entry = _parse_project_file(str(f))
    assert entry is not None
    assert entry.name == "my.cool.project"
    assert entry.port == 13339


def test_parse_project_file_invalid(tmp_path):
    f = tmp_path / "noport"
    f.touch()
    assert _parse_project_file(str(f)) is None


def test_parse_project_file_bad_port(tmp_path):
    f = tmp_path / "project.abc"
    f.touch()
    assert _parse_project_file(str(f)) is None


def test_register_project(tmp_config):
    path = register_project("road_rash", 13339)
    assert os.path.isfile(path)
    assert "road_rash.13339" in path
    assert os.path.getsize(path) == 0
    os.unlink(path)


def test_register_project_sanitizes_name(tmp_config):
    path = register_project("my project!@#", 13340)
    basename = os.path.basename(path)
    assert basename.endswith(".13340")
    assert "!" not in basename
    os.unlink(path)


def test_register_project_empty_name(tmp_config):
    path = register_project("", 13341)
    basename = os.path.basename(path)
    assert "project_13341" in basename
    os.unlink(path)


def test_unregister_project(tmp_config):
    register_project("test", 13339)
    assert unregister_project(13339) is True
    assert len(list_projects()) == 0


def test_unregister_project_not_found(tmp_config):
    assert unregister_project(99999) is False


def test_list_projects(tmp_config):
    register_project("alpha", 13339)
    register_project("beta", 13340)
    projects = list_projects()
    assert len(projects) == 2
    names = {p.name for p in projects}
    assert names == {"alpha", "beta"}
    unregister_project(13339)
    unregister_project(13340)


def test_list_projects_empty(tmp_config):
    assert list_projects() == []


def test_list_projects_ignores_hidden(tmp_config):
    (tmp_config / ".hidden.13339").touch()
    register_project("visible", 13340)
    projects = list_projects()
    assert len(projects) == 1
    assert projects[0].name == "visible"
    unregister_project(13340)


def test_find_project(tmp_config):
    register_project("target", 13339)
    entry = find_project("target")
    assert entry is not None
    assert entry.port == 13339
    unregister_project(13339)


def test_find_project_not_found(tmp_config):
    register_project("other", 13339)
    assert find_project("nonexistent") is None
    unregister_project(13339)


def test_cleanup_stale_projects(tmp_config):
    """Projects with dead ports should be cleaned up."""
    register_project("alive", 13339)
    register_project("dead", 59999)  # unlikely to be listening
    removed = cleanup_stale_projects()
    removed_ports = {e.port for e in removed}
    assert 59999 in removed_ports
    unregister_project(13339)
    unregister_project(59999)


def test_register_overwrites(tmp_config):
    """Registering the same project+port twice should work."""
    path1 = register_project("test", 13339)
    path2 = register_project("test", 13339)
    assert path1 == path2
    assert os.path.isfile(path2)
    unregister_project(13339)
