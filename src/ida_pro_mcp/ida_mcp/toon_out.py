"""TOON encoding for model-facing tool result text.

The MCP ``structuredContent`` field stays JSON (required by the MCP spec); only
the ``content[].text`` blocks the model actually reads are encoded as TOON
(Token-Oriented Object Notation) to cut token usage on tabular results such as
function/xref lists. Set ``IDA_MCP_OUTPUT_FORMAT=json`` to opt out globally and
keep the original compact JSON text.

Per-session overrides
---------------------
The default for every MCP session is TOON. Agents that strictly need JSON can
opt in for one session via the ``set_output_format`` tool in
``api_prefs.py``. Overrides live only in this process's memory, keyed by the
MCP transport session id, so concurrent agents each get independent settings
and nothing is persisted to the IDB.
"""
from __future__ import annotations

import json
import os
import threading
from typing import Any

TOON_ENABLED = os.environ.get("IDA_MCP_OUTPUT_FORMAT", "toon").strip().lower() not in (
    "json",
    "off",
    "0",
    "false",
)

VALID_FORMATS = ("toon", "json", "auto")

# Per-session override table. Key: transport session id (see
# MCP_SERVER.get_current_transport_session_id()). Value: one of VALID_FORMATS.
# Multiple agents can connect concurrently; each session has its own slot.
_OUTPUT_FORMAT_OVERRIDES: dict[str, str] = {}
_OUTPUT_FORMAT_LOCK = threading.Lock()


def _current_session_id() -> str | None:
    # Deferred import: rpc imports this module at load time.
    from .rpc import MCP_SERVER

    return MCP_SERVER.get_current_transport_session_id()


def set_session_format(format: str) -> str:
    """Set the output format override for the current MCP session.

    ``format`` must be one of ``VALID_FORMATS``. ``"auto"`` clears the override
    and falls back to the global default. Returns the effective format that
    subsequent tool calls will use (``"toon"`` or ``"json"``).

    Overrides live only in memory and reset when the MCP session ends. Other
    concurrent agents keep their own settings.
    """
    if format not in VALID_FORMATS:
        raise ValueError(
            f"Invalid format: {format!r}. Must be one of: {', '.join(VALID_FORMATS)}"
        )
    sid = _current_session_id() or "anonymous"
    with _OUTPUT_FORMAT_LOCK:
        if format == "auto":
            _OUTPUT_FORMAT_OVERRIDES.pop(sid, None)
        else:
            _OUTPUT_FORMAT_OVERRIDES[sid] = format
    return "toon" if resolve_use_toon() else "json"


def get_session_format() -> dict:
    """Return ``{override, effective}`` for the current MCP session.

    ``override`` is the explicit value the session last set, or ``None`` when
    the session has never called ``set_session_format`` (or has reverted to
    ``"auto"``). ``effective`` is what subsequent tool calls will actually use.
    """
    sid = _current_session_id() or "anonymous"
    with _OUTPUT_FORMAT_LOCK:
        override = _OUTPUT_FORMAT_OVERRIDES.get(sid)
    return {
        "override": override,
        "effective": "toon" if resolve_use_toon() else "json",
    }


def resolve_use_toon() -> bool:
    """Decide whether the current MCP session's tool output should be TOON.

    Per-session override wins over the global flag. ``"auto"`` (or no override)
    falls back to ``TOON_ENABLED``. The global default is TOON, so out of the
    box every session gets TOON unless ``IDA_MCP_OUTPUT_FORMAT`` is set in the
    environment or the session has called ``set_session_format``.
    """
    sid = _current_session_id() or "anonymous"
    with _OUTPUT_FORMAT_LOCK:
        override = _OUTPUT_FORMAT_OVERRIDES.get(sid)
    if override == "json":
        return False
    if override == "toon":
        return True
    return TOON_ENABLED


def to_llm_text(obj: Any) -> str:
    """Serialize a tool result for the model-facing text content.

    Encoding decision is per-session (``resolve_use_toon()``), not the global
    flag: a session that opted into JSON via ``set_output_format('json')`` must
    not get TOON encoded text on the oversized branch. Dicts and lists go to
    TOON when the session allows it; everything else falls back to compact
    JSON. Any encoder error also falls back to JSON, so tool output never
    breaks because of formatting.
    """
    if resolve_use_toon() and isinstance(obj, (dict, list)):
        try:
            import toon_py

            return toon_py.encode(obj)
        except Exception:
            pass
    return json.dumps(obj, separators=(",", ":"))