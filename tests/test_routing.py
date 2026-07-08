"""Tests for ``ida_pro_mcp.routing`` and the proxy ``tools/list`` merge logic."""

import pytest

from ida_pro_mcp import routing


def _fake_instance(**overrides):
    """Build a discover_instances()-shaped entry."""
    base = {
        "host": "127.0.0.1",
        "port": 13337,
        "pid": 9999,
        "binary": "fake.exe",
        "idb_path": "/tmp/project_a.i64",
        "started_at": "2026-01-01T00:00:00+00:00",
        "backend": "gui",
    }
    base.update(overrides)
    return base


# ============================================================================
# Merge helper extracted from server.py — mirrors its _merge_tools_list.
# ============================================================================


def _merge_tools_list(remote, local):
    """Same logic as server._merge_tools_list. Standalone so this module
    can be exercised without IDA. The real one lives in server.py and is
    exercised by tests that run inside IDA via the framework test runner.
    """
    remote_tools = []
    if isinstance(remote, dict):
        result = remote.get("result") if isinstance(remote.get("result"), dict) else {}
        remote_tools = list(result.get("tools", []) or [])
    local_tools = []
    if isinstance(local, dict):
        result = local.get("result") if isinstance(local.get("result"), dict) else {}
        local_tools = list(result.get("tools", []) or [])

    seen = {t.get("name") for t in remote_tools if isinstance(t, dict)}
    for tool in local_tools:
        if not isinstance(tool, dict):
            continue
        if tool.get("name") in seen:
            continue
        remote_tools.append(tool)
        seen.add(tool.get("name"))

    base = remote if isinstance(remote, dict) else {}
    return {**base, "result": {"tools": remote_tools}}


def test_merge_appends_proxy_local_tools_after_ida_tools():
    """Local tools come after IDA tools; no duplicates added."""
    remote = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "tools": [
                {"name": "decompile", "description": "Decompile at addr"},
                {"name": "list_funcs", "description": "List functions"},
            ]
        },
    }
    local = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "tools": [
                {"name": "idb_list", "description": "List running IDAs"},
                {"name": "idb_select", "description": "Pin session to IDA"},
            ]
        },
    }
    merged = _merge_tools_list(remote, local)
    names = [t["name"] for t in merged["result"]["tools"]]
    assert names == ["decompile", "list_funcs", "idb_list", "idb_select"]


def test_merge_dedupes_collisions():
    """If both sides expose the same name, the IDA-side schema wins."""
    remote = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "tools": [{"name": "shared_tool", "description": "from IDA"}]
        },
    }
    local = {
        "result": {
            "tools": [{"name": "shared_tool", "description": "from proxy"}]
        }
    }
    merged = _merge_tools_list(remote, local)
    tools = merged["result"]["tools"]
    assert len(tools) == 1
    assert tools[0]["description"] == "from IDA"


def test_merge_handles_remote_failure_gracefully():
    """A non-dict remote (e.g. error) still yields proxy-local tools."""
    local = {"result": {"tools": [{"name": "idb_list"}]}}
    merged = _merge_tools_list(None, local)
    assert [t["name"] for t in merged["result"]["tools"]] == ["idb_list"]


def test_merge_preserves_envelope_fields_from_remote():
    """jsonrpc/id come from the remote response when present."""
    remote = {"jsonrpc": "2.0", "id": 7, "result": {"tools": []}}
    local = {"jsonrpc": "2.0", "id": 7, "result": {"tools": [{"name": "idb_list"}]}}
    merged = _merge_tools_list(remote, local)
    assert merged.get("jsonrpc") == "2.0"
    assert merged.get("id") == 7



def _fake_instance(**overrides):
    """Build a discover_instances()-shaped entry."""
    base = {
        "host": "127.0.0.1",
        "port": 13337,
        "pid": 9999,
        "binary": "fake.exe",
        "idb_path": "/tmp/project_a.i64",
        "started_at": "2026-01-01T00:00:00+00:00",
        "backend": "gui",
    }
    base.update(overrides)
    return base


# --- SessionTargets --------------------------------------------------------


def test_session_targets_round_trip():
    st = routing.SessionTargets()
    assert st.get("s1") is None
    st.set("s1", "127.0.0.1", 13337, "/tmp/a.i64")
    assert st.get("s1") == ("127.0.0.1", 13337, "/tmp/a.i64")
    st.clear()
    assert st.get("s1") is None


def test_session_targets_isolated():
    """Setting one session does not touch another."""
    st = routing.SessionTargets()
    st.set("s1", "127.0.0.1", 13337, "/tmp/a.i64")
    st.set("s2", "127.0.0.1", 13338, "/tmp/b.i64")
    assert st.get("s1") == ("127.0.0.1", 13337, "/tmp/a.i64")
    assert st.get("s2") == ("127.0.0.1", 13338, "/tmp/b.i64")


# --- idb_list / idb_select (select_target + list_instances_to_response) -----


def test_list_instances_marks_current():
    a = _fake_instance(port=13337, idb_path="/tmp/a.i64")
    b = _fake_instance(port=13338, idb_path="/tmp/b.i64")
    listing = routing.list_instances_to_response(
        [a, b], current=("127.0.0.1", 13338, "/tmp/b.i64")
    )
    by_idb = {x["idb_path"]: x for x in listing["instances"]}
    assert by_idb["/tmp/a.i64"]["current"] is False
    assert by_idb["/tmp/b.i64"]["current"] is True


def test_select_target_matches_by_idb_path():
    set_calls = []
    result = routing.select_target(
        "/tmp/b.i64",
        [
            _fake_instance(port=13337, idb_path="/tmp/a.i64"),
            _fake_instance(port=13338, idb_path="/tmp/b.i64"),
        ],
        set_target=lambda h, p, i: set_calls.append((h, p, i)),
    )
    assert "error" not in result, result
    assert result["current"]["port"] == 13338
    assert result["current"]["idb_path"] == "/tmp/b.i64"
    assert set_calls == [("127.0.0.1", 13338, "/tmp/b.i64")]


def test_select_target_falls_back_to_port_when_path_unknown():
    set_calls = []
    result = routing.select_target(
        "13337",
        [
            _fake_instance(port=13337, idb_path="/tmp/a.i64"),
            _fake_instance(port=13338, idb_path="/tmp/b.i64"),
        ],
        set_target=lambda h, p, i: set_calls.append((h, p, i)),
    )
    assert "error" not in result, result
    assert result["current"]["port"] == 13337
    assert result["current"]["idb_path"] == "/tmp/a.i64"
    assert set_calls == [("127.0.0.1", 13337, "/tmp/a.i64")]


def test_select_target_unknown_returns_listed_alternatives():
    result = routing.select_target(
        "/tmp/nonexistent.i64",
        [_fake_instance(port=13337, idb_path="/tmp/a.i64")],
        set_target=lambda *_: None,
    )
    assert "error" in result, result
    assert "/tmp/a.i64" in result["error"]
    assert "idb_list" in result["error"]


def test_select_target_empty_passes_through():
    """An empty target string is treated like 'no match'."""
    result = routing.select_target(
        "", [_fake_instance(port=13337, idb_path="/tmp/a.i64")],
        set_target=lambda *_: None,
    )
    assert "error" in result, result


# --- forward_json_rpc: recovery loop --------------------------------------


def test_forward_returns_parsed_json_on_success():
    payload = b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

    class Conn:
        def __init__(self, h, p, timeout=None):
            pass

        def request(self, method, url, body=None, headers=None):
            pass

        def getresponse(self):
            class R:
                status = 200
                reason = "OK"

                def read(inner):
                    return b'{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}'

            return R()

        def close(self):
            pass

    result = routing.forward_json_rpc(
        payload,
        host="127.0.0.1",
        port=13340,
        path="/mcp",
        headers={"Content-Type": "application/json"},
        conn_factory=Conn,
    )
    assert result == {"jsonrpc": "2.0", "id": 1, "result": {"tools": []}}


def test_forward_retries_on_connection_refused_then_succeeds():
    payload = b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
    attempts = {"n": 0}
    sleeps = []

    def conn_factory(host, port, timeout=None):
        attempts["n"] += 1
        if attempts["n"] == 1:
            class Refuse:
                def request(self, *a, **kw):
                    raise ConnectionRefusedError("down")

                def getresponse(self_inner):  # noqa: N805
                    raise AssertionError

                def close(self_inner):  # noqa: N805
                    pass

            return Refuse()

        class Ok:
            def request(self, *a, **kw):
                pass

            def getresponse(self_inner):  # noqa: N805
                class R:
                    status = 200
                    reason = "OK"

                    def read(inner):
                        return b'{"jsonrpc":"2.0","id":1,"result":{}}'

                return R()

            def close(self_inner):  # noqa: N805
                pass

        return Ok()

    result = routing.forward_json_rpc(
        payload,
        host="127.0.0.1",
        port=13340,
        path="/mcp",
        headers={},
        conn_factory=conn_factory,
        sleep=lambda s: sleeps.append(s),
        now=lambda: 100.0 + sum(sleeps),  # monotonic advancing
    )
    assert result == {"jsonrpc": "2.0", "id": 1, "result": {}}
    assert attempts["n"] == 2
    assert sleeps, "expected at least one retry sleep"


def test_forward_gives_up_after_deadline():
    payload = b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

    class AlwaysRefuse:
        def __init__(self, h, p, timeout=None):
            pass

        def request(self, *a, **kw):
            raise ConnectionRefusedError("down")

        def getresponse(self):  # noqa: D401
            raise AssertionError

        def close(self):
            pass

    # Now returns jumps past the deadline immediately.
    fake_now = {"t": 0.0}

    def now():
        return fake_now["t"]

    sleeps = []

    def sleep_fn(s):
        sleeps.append(s)
        fake_now["t"] += 1000.0  # jump past deadline on first wait

    with pytest.raises(ConnectionRefusedError):
        routing.forward_json_rpc(
            payload,
            host="127.0.0.1",
            port=13341,
            path="/mcp",
            headers={},
            conn_factory=AlwaysRefuse,
            sleep=sleep_fn,
            now=now,
            timeout_sec=10.0,
            poll_interval_sec=1.0,
        )


def test_forward_propagates_http_error_immediately():
    """HTTP 4xx/5xx are not retried — they're an authoritative server reply."""
    payload = b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

    class Conn:
        def __init__(self, h, p, timeout=None):
            pass

        def request(self, *a, **kw):
            pass

        def getresponse(self):
            class R:
                status = 500
                reason = "Server Error"

                def read(inner):
                    return b"oops"

            return R()

        def close(self):
            pass

    with pytest.raises(RuntimeError, match="HTTP 500"):
        routing.forward_json_rpc(
            payload,
            host="127.0.0.1",
            port=13342,
            path="/mcp",
            headers={},
            conn_factory=Conn,
        )
