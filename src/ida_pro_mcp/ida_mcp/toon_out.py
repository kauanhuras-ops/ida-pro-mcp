"""TOON encoding for model-facing tool result text.

In TOON mode, analysis tools re-render ``content[].text`` as TOON (Token-
Oriented Object Notation) to cut token usage on tabular results such as
function/xref lists, and **drop** ``structuredContent``. Some clients (e.g.
Claude Code) read ``structuredContent`` over ``content[].text``; keeping the
JSON ``structuredContent`` would bypass TOON entirely, so it is removed for
analysis tools and the client falls back to the TOON text.

Management tools (``TOON_EXEMPT_TOOLS``: health, idb switching, format
switching) are exempt: they keep ``structuredContent`` and compact JSON text
even in TOON mode, forming a stable JSON control plane. This lets strict
clients (e.g. Pi Agent, which validates ``outputSchema -> structuredContent``)
probe health and call ``set_output_format('json')`` up front, after which their
analysis calls come back as JSON. Set ``IDA_MCP_OUTPUT_FORMAT=json`` to opt out
globally and keep JSON everywhere.

Worker override
---------------
Each worker process has one output format. All clients routed to that worker
share it. Separate workers have separate settings, even when they open the same
IDB. The override lives only in the worker process's memory and is not stored
in the IDB.
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

# One override per worker process. Separate worker processes do not share this
# module state, even when they open the same IDB.
_OUTPUT_FORMAT_OVERRIDE: str | None = None
_OUTPUT_FORMAT_LOCK = threading.Lock()


def _use_toon_for_override(override: str | None) -> bool:
    if override == "json":
        return False
    if override == "toon":
        return True
    return TOON_ENABLED


def set_worker_format(format: str) -> str:
    """Set the output format override for this worker process.

    ``format`` must be one of ``VALID_FORMATS``. ``"auto"`` clears the override
    and falls back to the global default. Returns the effective format that
    subsequent tool calls will use (``"toon"`` or ``"json"``).

    All clients routed to this worker share the setting. Other worker processes
    keep their own settings, including workers that open the same IDB.
    """
    global _OUTPUT_FORMAT_OVERRIDE
    if format not in VALID_FORMATS:
        raise ValueError(
            f"Invalid format: {format!r}. Must be one of: {', '.join(VALID_FORMATS)}"
        )
    with _OUTPUT_FORMAT_LOCK:
        _OUTPUT_FORMAT_OVERRIDE = None if format == "auto" else format
        use_toon = _use_toon_for_override(_OUTPUT_FORMAT_OVERRIDE)
    return "toon" if use_toon else "json"


def get_worker_format() -> dict:
    """Return ``{override, effective}`` for this worker process.

    ``override`` is the explicit value last set on this worker, or ``None``
    after ``"auto"``. ``effective`` is what subsequent tool calls will use.
    """
    with _OUTPUT_FORMAT_LOCK:
        override = _OUTPUT_FORMAT_OVERRIDE
        use_toon = _use_toon_for_override(override)
    return {
        "override": override,
        "effective": "toon" if use_toon else "json",
    }


def resolve_use_toon() -> bool:
    """Decide whether this worker's tool output should be TOON.

    The worker override wins over the global flag. ``"auto"`` (or no override)
    falls back to ``TOON_ENABLED``.
    """
    with _OUTPUT_FORMAT_LOCK:
        return _use_toon_for_override(_OUTPUT_FORMAT_OVERRIDE)


# Management/control tools are always served as JSON — structuredContent kept,
# text not TOON-encoded — even when the session is in TOON mode. They form a
# stable JSON control plane so strict clients (e.g. Pi Agent, which validates
# outputSchema -> structuredContent) can probe health and flip the worker to
# JSON via ``set_output_format('json')`` before issuing analysis calls.
# Analysis tools follow the worker's TOON/JSON preference.
TOON_EXEMPT_TOOLS = frozenset({
    "server_health",
    "idb_open",
    "idb_list",
    "idb_select",
    "idb_current",
    "set_output_format",
    "get_output_format",
})


def should_toon(name: str | None) -> bool:
    """Whether the tool ``name`` should be TOON-encoded by this worker.

    Management tools are exempt: they keep ``structuredContent`` and compact
    JSON text regardless of the worker format, so strict clients can always
    parse control responses. All other tools follow the worker preference.
    """
    return resolve_use_toon() and name not in TOON_EXEMPT_TOOLS


def to_llm_text(obj: Any, force_json: bool = False) -> str:
    """Serialize a tool result for the model-facing text content.

    Encoding follows the worker override (``resolve_use_toon()``), not only the
    global flag: a worker set to JSON via ``set_output_format('json')`` must
    not get TOON encoded text on the oversized branch. Dicts and lists go to
    TOON when the worker allows it; everything else falls back to compact
    JSON. Any encoder error also falls back to JSON, so tool output never
    breaks because of formatting. ``force_json`` overrides the worker check
    (used for management tools that are exempt from TOON even in TOON mode).
    """
    if not force_json and resolve_use_toon() and isinstance(obj, (dict, list)):
        try:
            import toon_py

            return toon_py.encode(obj)
        except Exception:
            pass
    return json.dumps(obj, separators=(",", ":"))


def mode_info() -> dict:
    """Return the output-mode fields for health/inspection endpoints.

    ``mode`` is the worker's effective format (``'toon'`` or ``'json'``).
    When TOON is active, a prominent ``!important`` field explains how to
    toggle it, so clients reading the always-JSON health response know how to
    opt out (e.g. Pi Agent switching to JSON for structured-output validation).
    """
    mode = "toon" if resolve_use_toon() else "json"
    info: dict = {"mode": mode}
    if mode == "toon":
        info["!important"] = (
            "Analysis tool output is TOON (compact, non-JSON). "
            "Switch this worker to JSON with set_output_format('json'), "
            "revert to the server default with set_output_format('auto'), or "
            "disable globally via the IDA_MCP_OUTPUT_FORMAT=json env var."
        )
    return info
