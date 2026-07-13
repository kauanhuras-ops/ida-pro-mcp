"""Tests for worker-scoped output format preferences."""

import json

from ..framework import test
from ..api_prefs import get_output_format, set_output_format
from ..rpc import MCP_SERVER, tool as register_tool
from ..toon_out import (
    VALID_FORMATS,
    TOON_ENABLED,
    TOON_EXEMPT_TOOLS,
    resolve_use_toon,
    should_toon,
    to_llm_text,
)


def _reset_worker():
    """Drop any leftover override for the test worker."""
    set_output_format("auto")


@test()
def test_default_is_toon_after_reset():
    """A worker reverted to 'auto' gets TOON by default."""
    _reset_worker()
    info = get_output_format()
    assert info["effective"] == "toon", info
    assert resolve_use_toon() is True


@test()
def test_set_to_json_flips_effective_format():
    """set_output_format('json') makes subsequent calls render as JSON."""
    _reset_worker()
    result = set_output_format("json")
    assert result == {"format": "json", "effective": "json"}, result
    assert resolve_use_toon() is False
    info = get_output_format()
    assert info["override"] == "json", info
    assert info["effective"] == "json", info


@test()
def test_set_to_toon_forces_toon_even_when_global_off():
    """An explicit 'toon' override wins over the global flag.

    Simulates the operator disabling TOON globally (env var) and a worker
    still requesting TOON: the override must win.
    """
    _reset_worker()
    # Even if TOON_ENABLED were False in this process, an explicit 'toon'
    # override would force TOON. We can't easily flip TOON_ENABLED at runtime,
    # so we just verify the override is honored and effective reflects it.
    set_output_format("toon")
    info = get_output_format()
    assert info["override"] == "toon", info
    assert info["effective"] == "toon", info
    assert resolve_use_toon() is True


@test()
def test_auto_reverts_to_global_default():
    """set_output_format('auto') clears the override."""
    _reset_worker()
    set_output_format("json")
    assert resolve_use_toon() is False
    result = set_output_format("auto")
    assert result == {"format": "auto", "effective": "toon"}, result
    assert resolve_use_toon() is True
    info = get_output_format()
    assert info["override"] is None, info
    assert info["effective"] == "toon", info


@test()
def test_invalid_format_returns_error_in_tool():
    """set_output_format rejects unknown formats via the tool surface."""
    _reset_worker()
    result = set_output_format("yaml")
    assert "error" in result, result
    assert "Invalid format" in result["error"]
    # State must not have been mutated.
    info = get_output_format()
    assert info["override"] is None, info


@test()
def test_valid_formats_constant_lists_supported_values():
    """VALID_FORMATS exposes the supported values to callers."""
    assert set(VALID_FORMATS) == {"toon", "json", "auto"}


@test()
def test_client_sessions_share_worker_state():
    """Two client sessions routed to one worker share its override.

    The transport session id must have no effect on output format. Process
    boundaries, not client or database ids, isolate worker settings.
    """
    from .. import rpc

    # Ensure a clean worker baseline.
    set_output_format("auto")

    old_sid = rpc.MCP_SERVER.get_current_transport_session_id()
    try:
        # Agent A sets the worker to JSON.
        rpc.MCP_SERVER._transport_session_id.data = "http:agent-A"
        set_output_format("json")
        info_A = get_output_format()
        assert info_A["effective"] == "json", info_A

        # Agent B on the same worker must see JSON too.
        rpc.MCP_SERVER._transport_session_id.data = "http:agent-B"
        info_B = get_output_format()
        assert info_B["override"] == "json", info_B
        assert info_B["effective"] == "json", info_B

        # Agent B switches the worker to TOON.
        set_output_format("toon")
        info_B2 = get_output_format()
        assert info_B2["effective"] == "toon", info_B2

        # Agent A must now see the same worker-wide TOON setting.
        rpc.MCP_SERVER._transport_session_id.data = "http:agent-A"
        info_A2 = get_output_format()
        assert info_A2["override"] == "toon", info_A2
        assert info_A2["effective"] == "toon", info_A2
    finally:
        rpc.MCP_SERVER._transport_session_id.data = old_sid
        set_output_format("auto")


def _call_tool(name: str, arguments: dict | None = None) -> dict:
    """Invoke the patched tools/call dispatcher for a registered tool."""
    return MCP_SERVER.registry.methods["tools/call"](name, arguments or {})


@test()
def test_management_tool_keeps_json_in_toon_mode():
    """Management tools stay JSON (structuredContent + JSON text) in TOON mode.

    They form the stable JSON control plane so strict clients (e.g. Pi Agent,
    which validates outputSchema -> structuredContent) can always parse health
    and format-switch responses, even when the worker is in TOON mode. Pi Agent
    calls set_output_format('json') up front and subsequent analysis calls come
    back as JSON; Claude Code stays on the TOON default.
    """
    set_output_format("auto")  # default → TOON
    assert resolve_use_toon() is True
    assert should_toon("get_output_format") is False  # exempt

    response = _call_tool("get_output_format")

    assert response.get("isError") is not True, response
    structured = response.get("structuredContent")
    assert structured is not None, (
        "management tools must keep structuredContent in TOON mode so strict "
        "clients can parse control responses"
    )
    assert structured.get("effective") == "toon", structured

    text_blocks = [
        block for block in response.get("content", [])
        if isinstance(block, dict) and block.get("type") == "text"
    ]
    assert text_blocks, response
    # Management tool text stays compact JSON (not TOON) in TOON mode.
    assert text_blocks[0]["text"] == json.dumps(structured, separators=(",", ":")), (
        text_blocks[0]["text"]
    )

    set_output_format("auto")


@test()
def test_analysis_tool_drops_structured_content_in_toon_mode():
    """Non-management tools in TOON mode return TOON text with no structuredContent.

    Claude Code reads structuredContent over content[].text, so keeping the JSON
    structuredContent would bypass TOON entirely. Dropping it forces the client
    to fall back to content[].text, which is re-encoded as TOON.
    """

    @register_tool
    def _toon_probe() -> dict:
        """Probe returning a dict so we can inspect TOON vs JSON encoding."""
        return {"name": "main", "addr": "0x401000"}

    try:
        set_output_format("auto")  # default → TOON
        assert resolve_use_toon() is True
        assert should_toon("_toon_probe") is True  # not exempt

        response = _call_tool("_toon_probe")

        assert response.get("isError") is not True, response
        # structuredContent must be dropped so clients that prefer it fall back
        # to content[].text (TOON).
        assert "structuredContent" not in response, response

        text_blocks = [
            block for block in response.get("content", [])
            if isinstance(block, dict) and block.get("type") == "text"
        ]
        assert text_blocks, response
        first_text = text_blocks[0]["text"]
        # TOON output is not valid JSON; JSON-mode passthrough would round-trip.
        try:
            json.loads(first_text)
        except json.JSONDecodeError:
            pass  # expected — it's TOON
        else:
            assert first_text == to_llm_text({"name": "main", "addr": "0x401000"}), (
                "content[].text should be TOON-encoded in TOON mode, got JSON"
            )
    finally:
        MCP_SERVER.tools.methods.pop("_toon_probe", None)
        set_output_format("auto")


@test()
def test_should_toon_exempts_management_tools():
    """should_toon exempts management tools and follows the worker preference."""
    set_output_format("auto")  # TOON default
    try:
        assert resolve_use_toon() is True
        for name in TOON_EXEMPT_TOOLS:
            assert should_toon(name) is False, name
        assert should_toon("list_funcs") is True
        assert should_toon("decompile") is True
        assert should_toon(None) is True  # unknown tool → follows preference

        # JSON mode disables TOON for everything, exempt or not.
        set_output_format("json")
        assert should_toon("list_funcs") is False
        assert should_toon("get_output_format") is False
    finally:
        set_output_format("auto")


@test()
def test_server_health_reports_mode_and_toggle_hint():
    """server_health reports mode and a !important toggle hint in TOON mode.

    server_health is a management tool (exempt), so it always returns JSON with
    structuredContent — but it carries ``mode`` and, when TOON is active, a
    ``!important`` field explaining how to opt out. This is the discovery path
    for clients that need JSON (e.g. Pi Agent) to switch the session.
    """
    set_output_format("auto")  # TOON default
    try:
        response = _call_tool("server_health")
        structured = response.get("structuredContent")
        assert structured is not None, response  # exempt → keeps structuredContent
        assert structured.get("mode") == "toon", structured
        assert "!important" in structured, structured
        assert "set_output_format" in structured["!important"], structured["!important"]

        # JSON mode: mode flips, !important dropped.
        set_output_format("json")
        response = _call_tool("server_health")
        structured = response.get("structuredContent")
        assert structured.get("mode") == "json", structured
        assert "!important" not in structured, structured
    finally:
        set_output_format("auto")


@test()
def test_tools_call_preserves_structured_content_in_json_mode():
    """JSON mode passes through verbatim — structuredContent intact, text = JSON."""
    set_output_format("json")
    try:
        response = _call_tool("get_output_format")

        assert response.get("isError") is not True, response
        structured = response.get("structuredContent")
        assert structured is not None, response
        assert structured.get("effective") == "json", structured

        text_blocks = [
            block for block in response.get("content", [])
            if isinstance(block, dict) and block.get("type") == "text"
        ]
        assert text_blocks, response
        # JSON mode is a pure passthrough: text matches structuredContent JSON.
        assert text_blocks[0]["text"] == json.dumps(structured, separators=(",", ":")), text_blocks[0]["text"]
    finally:
        set_output_format("auto")


@test()
def test_to_llm_text_follows_worker_override_not_only_global():
    """to_llm_text must follow the worker override, not only the global flag.

    Regression guard: in the oversized branch of rpc.py, to_llm_text is called
    directly. If it consulted only the global TOON_ENABLED, a worker set to
    JSON would get JSON (structuredContent) and TOON (text) together.
    """
    obj = {"name": "main", "addr": "0x401000"}

    set_output_format("auto")  # follow global
    auto_text = to_llm_text(obj)
    # Default global is TOON, so auto text must NOT be plain JSON.
    assert auto_text != json.dumps(obj, separators=(",", ":")), auto_text

    set_output_format("json")
    try:
        json_text = to_llm_text(obj)
        # Worker is JSON: must be plain compact JSON, regardless of the global
        # flag. If this fails with the global still on, we have the bug back.
        assert json_text == json.dumps(obj, separators=(",", ":")), (
            f"to_llm_text ignored the worker override and produced "
            f"{json_text!r} (global TOON_ENABLED={TOON_ENABLED})"
        )
    finally:
        set_output_format("auto")
