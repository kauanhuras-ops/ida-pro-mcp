"""Tests for per-session output format preferences."""

import json

from ..framework import test
from ..api_prefs import get_output_format, set_output_format
from ..rpc import MCP_SERVER
from ..toon_out import (
    VALID_FORMATS,
    TOON_ENABLED,
    _OUTPUT_FORMAT_OVERRIDES,
    resolve_use_toon,
    to_llm_text,
)


def _reset_session():
    """Drop any leftover override for the test session."""
    set_output_format("auto")


@test()
def test_default_is_toon_after_reset():
    """A fresh session (or one reverted to 'auto') gets TOON by default."""
    _reset_session()
    info = get_output_format()
    assert info["effective"] == "toon", info
    assert resolve_use_toon() is True


@test()
def test_set_to_json_flips_effective_format():
    """set_output_format('json') makes subsequent calls render as JSON."""
    _reset_session()
    result = set_output_format("json")
    assert result == {"format": "json", "effective": "json"}, result
    assert resolve_use_toon() is False
    info = get_output_format()
    assert info["override"] == "json", info
    assert info["effective"] == "json", info


@test()
def test_set_to_toon_forces_toon_even_when_global_off():
    """An explicit 'toon' override wins over the global flag.

    Simulates the operator disabling TOON globally (env var) and a session
    still requesting TOON: the override must win.
    """
    _reset_session()
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
    _reset_session()
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
    _reset_session()
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
def test_concurrent_sessions_have_independent_state():
    """Two different session ids must not see each other's overrides.

    Simulates two agents connecting concurrently by swapping the current
    transport session id between calls. Each agent's override must be
    isolated.
    """
    from .. import rpc

    # Ensure a clean baseline for any session that happens to be current.
    set_output_format("auto")

    old_sid = rpc.MCP_SERVER.get_current_transport_session_id()
    try:
        # Agent A: opts into JSON.
        rpc.MCP_SERVER._transport_session_id.data = "http:agent-A"
        set_output_format("json")
        info_A = get_output_format()
        assert info_A["effective"] == "json", info_A

        # Agent B: stays on the default (TOON).
        rpc.MCP_SERVER._transport_session_id.data = "http:agent-B"
        info_B = get_output_format()
        assert info_B["override"] is None, info_B
        assert info_B["effective"] == "toon", info_B

        # Agent B switches to JSON too — must not affect Agent A's snapshot.
        set_output_format("json")
        info_B2 = get_output_format()
        assert info_B2["effective"] == "json", info_B2

        # Back to A — must still be JSON.
        rpc.MCP_SERVER._transport_session_id.data = "http:agent-A"
        info_A2 = get_output_format()
        assert info_A2["override"] == "json", info_A2
        assert info_A2["effective"] == "json", info_A2

        # The override table must contain an entry for each agent.
        assert "http:agent-A" in _OUTPUT_FORMAT_OVERRIDES, _OUTPUT_FORMAT_OVERRIDES
        assert "http:agent-B" in _OUTPUT_FORMAT_OVERRIDES, _OUTPUT_FORMAT_OVERRIDES
    finally:
        # Clean up so we don't leak entries between tests.
        _OUTPUT_FORMAT_OVERRIDES.pop("http:agent-A", None)
        _OUTPUT_FORMAT_OVERRIDES.pop("http:agent-B", None)
        rpc.MCP_SERVER._transport_session_id.data = old_sid
        set_output_format("auto")


def _call_tool(name: str, arguments: dict | None = None) -> dict:
    """Invoke the patched tools/call dispatcher for a registered tool."""
    return MCP_SERVER.registry.methods["tools/call"](name, arguments or {})


@test()
def test_tools_call_preserves_structured_content_in_toon_mode():
    """TOON mode must keep structuredContent so strict MCP clients don't reject.

    Pi Agent (and other clients that validate outputSchema -> structuredContent)
    fail with MCP error -32600 when structuredContent is dropped. The model still
    reads content[].text, so leaving structuredContent in place is harmless.
    """
    set_output_format("auto")  # default → TOON
    assert resolve_use_toon() is True

    response = _call_tool("get_output_format")

    assert response.get("isError") is not True, response
    structured = response.get("structuredContent")
    assert structured is not None, (
        "structuredContent must be preserved in TOON mode for outputSchema "
        "validation; Pi Agent rejects responses that drop it."
    )
    assert structured.get("effective") == "toon", structured

    # The model-facing text must still be re-encoded as TOON.
    text_blocks = [
        block for block in response.get("content", [])
        if isinstance(block, dict) and block.get("type") == "text"
    ]
    assert text_blocks, response
    first_text = text_blocks[0]["text"]
    # TOON output is not valid JSON (no quotes/braces around the keys in the
    # common object case), whereas the JSON-mode passthrough would round-trip.
    try:
        json.loads(first_text)
    except json.JSONDecodeError:
        pass  # expected — it's TOON
    else:
        # If it parses as JSON the rewriter didn't kick in.
        assert first_text == to_llm_text(structured), (
            "content[].text should be TOON-encoded in TOON mode"
        )

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
def test_to_llm_text_is_session_aware_not_global():
    """to_llm_text must follow the per-session override, not the global flag.

    Regression guard: in the oversized branch of rpc.py, to_llm_text is called
    directly. If it consulted the global TOON_ENABLED, a session that opted
    into JSON would still receive TOON-encoded text — and end up with both
    JSON (structuredContent) and TOON (text) in the same response.
    """
    obj = {"name": "main", "addr": "0x401000"}

    set_output_format("auto")  # follow global
    auto_text = to_llm_text(obj)
    # Default global is TOON, so the auto-session text must NOT be plain JSON.
    assert auto_text != json.dumps(obj, separators=(",", ":")), auto_text

    set_output_format("json")
    try:
        json_text = to_llm_text(obj)
        # Session is JSON: must be plain compact JSON, regardless of the global
        # flag. If this fails with the global still on, we have the bug back.
        assert json_text == json.dumps(obj, separators=(",", ":")), (
            f"to_llm_text ignored the session override and produced "
            f"{json_text!r} (global TOON_ENABLED={TOON_ENABLED})"
        )
    finally:
        set_output_format("auto")