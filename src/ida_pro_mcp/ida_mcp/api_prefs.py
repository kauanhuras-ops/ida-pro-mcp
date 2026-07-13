"""Worker-scoped output format preference.

Tools:
- ``set_output_format`` — switch the current worker between TOON (default)
  and JSON. ``"auto"`` reverts to the global default.
- ``get_output_format`` — report the active override and effective format.

The default for every worker is TOON. Some clients strictly expect JSON; they
call ``set_output_format('json')`` on their worker and subsequent tool calls
from that worker come back as compact JSON.

Over the MCP server:

- All clients routed to one worker share its setting.
- Separate worker processes have separate settings, even when they open the
  same IDB.
- The override lives only in process memory. It is never written to the IDB,
  and it disappears when the worker stops.
- The global default can still be flipped by the operator via the
  ``IDA_MCP_OUTPUT_FORMAT`` env var (``json`` / ``off`` / ``0`` / ``false``
  disables TOON). The worker override wins over the global flag.
"""
from typing import Annotated

from .rpc import tool
from .sync import idasync
from .toon_out import get_worker_format, set_worker_format


@tool
@idasync
def set_output_format(
    format: Annotated[
        str,
        "Output format for this worker: 'toon' (compact token-oriented "
        "notation, default), 'json' (compact JSON for clients that require it), "
        "or 'auto' (follow the server's global default). Applies only to the "
        "current worker process; other workers keep their own settings.",
    ],
) -> dict:
    """Set the output format for the current worker process.

    The server's default output format is TOON. Call this tool once with
    ``format='json'`` if your client strictly expects JSON; call with
    ``format='auto'`` to revert to the global default. The override lives only
    in this worker process and is not stored in the IDB. All clients routed to
    this worker share it; other workers keep their own setting.
    """
    try:
        effective = set_worker_format(format)
    except ValueError as exc:
        return {"error": str(exc)}
    return {"format": format, "effective": effective}


@tool
@idasync
def get_output_format() -> dict:
    """Return the current output format settings for this worker process.

    Reports the explicit override (``toon`` / ``json``), or ``None`` after
    ``auto``, and the effective format (``toon`` / ``json``) that subsequent
    tool calls will use.
    """
    return get_worker_format()
