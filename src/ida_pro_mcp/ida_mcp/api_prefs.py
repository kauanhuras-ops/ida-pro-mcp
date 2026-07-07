"""Per-MCP-session output format preferences.

Tools:
- ``set_output_format`` — switch the current session between TOON (default)
  and JSON. ``"auto"`` reverts to the global default.
- ``get_output_format`` — report the active override and effective format.

The default for every session is TOON. Some agents strictly expect JSON; they
call ``set_output_format('json')`` once at the start of the session and
subsequent tool calls come back as compact JSON.

Over the MCP server:

- Multiple agents may be connected concurrently. Each agent's HTTP request is
  keyed by its own ``Mcp-Session-Id`` (or ``stdio:default``), so the override
  table is naturally per-session — agents do not see each other's settings.
- The override lives only in process memory. It is never written to the IDB,
  never persisted across server restarts, and disappears with the session.
- The global default can still be flipped by the operator via the
  ``IDA_MCP_OUTPUT_FORMAT`` env var (``json`` / ``off`` / ``0`` / ``false``
  disables TOON). Per-session overrides win over the global flag.
"""
from typing import Annotated

from .rpc import tool
from .sync import idasync
from .toon_out import get_session_format, set_session_format


@tool
@idasync
def set_output_format(
    format: Annotated[
        str,
        "Output format for this MCP session: 'toon' (compact token-oriented "
        "notation, default), 'json' (compact JSON for clients that require it), "
        "or 'auto' (follow the server's global default). Applies only to the "
        "current MCP session; other connected agents keep their own settings.",
    ],
) -> dict:
    """Set the output format for the current MCP session.

    The server's default output format is TOON. Call this tool once with
    ``format='json'`` if your client strictly expects JSON; call with
    ``format='auto'`` to revert to the global default. The override lives only
    in this MCP session and is not stored in the IDB.
    """
    try:
        effective = set_session_format(format)
    except ValueError as exc:
        return {"error": str(exc)}
    return {"format": format, "effective": effective}


@tool
@idasync
def get_output_format() -> dict:
    """Return the current output format settings for this MCP session.

    Reports the explicit override (``toon`` / ``json`` / ``auto`` / ``None``)
    and the effective format (``toon`` / ``json``) that subsequent tool calls
    will use.
    """
    return get_session_format()