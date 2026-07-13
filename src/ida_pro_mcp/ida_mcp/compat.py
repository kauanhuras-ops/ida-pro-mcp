"""
IDA Pro 9.4 API helpers.

The public runtime target is IDA 9.4+. Address-based function, segment, frame,
and iterator APIs live here so server modules do not fall back to deprecated
pointer-based calls.
"""

from __future__ import annotations

from typing import Callable

import ida_bytes
import ida_entry
import ida_funcs
import ida_gdl
import ida_ida
import ida_nalt
import ida_typeinf
import ida_idaapi
import ida_segment

# ============================================================================
# Entry points
# ============================================================================


def get_entry_qty() -> int:
    return ida_entry.get_entry_qty()


def get_entry_ordinal(idx: int) -> int:
    return ida_entry.get_entry_ordinal(idx)


def get_entry(ordinal: int) -> int:
    return ida_entry.get_entry(ordinal)


def get_entry_name(ordinal: int) -> str | None:
    return ida_entry.get_entry_name(ordinal)


# ============================================================================
# Type ordinals
# ============================================================================


def get_ordinal_limit(til: ida_typeinf.til_t | None = None) -> int:
    return (
        ida_typeinf.get_ordinal_limit(til)
        if til is not None
        else ida_typeinf.get_ordinal_limit()
    )


# ============================================================================
# Database bounds
# ============================================================================


def inf_get_min_ea() -> int:
    return ida_ida.inf_get_min_ea()


def inf_get_max_ea() -> int:
    return ida_ida.inf_get_max_ea()


def inf_get_omin_ea() -> int:
    return ida_ida.inf_get_omin_ea()


def inf_get_omax_ea() -> int:
    return ida_ida.inf_get_omax_ea()


def inf_is_64bit() -> bool:
    return ida_ida.inf_is_64bit()


# ============================================================================
# IDA 9.4 address-based database access
# ============================================================================


def get_func(ea: int) -> ida_funcs.func_entry_info_t | None:
    """Return IDA 9.4 function entry information for any address in a function."""
    info = ida_funcs.func_entry_info_t()
    if ida_funcs.get_func_entry_info(info, ea):
        return info
    return None


def get_func_name(func: ida_funcs.func_entry_info_t) -> str | None:
    return ida_funcs.get_func_name(func.start_ea)


def get_func_prototype(
    func: ida_funcs.func_entry_info_t,
) -> ida_typeinf.tinfo_t | None:
    tif = ida_typeinf.tinfo_t()
    if ida_nalt.get_tinfo(tif, func.start_ea) and tif.is_func():
        return tif
    return None


class FlowChart:
    """Iterable IDA 9.4 flow chart built from a function address."""

    def __init__(self, func_ea: int, flags: int = 0):
        self._q = ida_gdl.qflow_chart_ea_t(
            "", func_ea, ida_idaapi.BADADDR, ida_idaapi.BADADDR, flags
        )

    @property
    def size(self) -> int:
        return self._q.size()

    def __iter__(self):
        return (
            ida_gdl.BasicBlock(index, self._q[index], self)
            for index in range(self.size)
        )

    def __getitem__(self, index: int):
        if index >= self.size:
            raise KeyError(index)
        return ida_gdl.BasicBlock(index, self._q[index], self)


def func_items(ea: int):
    """Yield code items in a function using IDA 9.4's address-based iterator."""
    iterator = ida_funcs.function_item_iterator_t(ea)
    if not iterator.first():
        return
    yield iterator.current()
    while iterator.next_code():
        yield iterator.current()


def functions():
    """Yield function entry addresses using IDA 9.4's ordinal API."""
    for index in range(ida_funcs.get_func_qty()):
        ea = ida_funcs.get_func_ea_by_num(index)
        if ea != ida_idaapi.BADADDR:
            yield ea


def get_segment(ea: int) -> ida_segment.segment_info_t | None:
    """Return IDA 9.4 segment information for an address."""
    info = ida_segment.segment_info_t()
    if ida_segment.get_segment_info(info, ea):
        return info
    return None


def get_segment_name(ea: int) -> str:
    """Return the IDA 9.4 segment name for an address, or an empty string."""
    return ida_segment.get_segment_name(ea) or ""


# ============================================================================
# Binary search
# ============================================================================


def raw_bin_search(
    ea: int,
    max_ea: int,
    data: bytes,
    mask: bytes,
    flags: int = 0,
) -> int:
    return ida_bytes.find_bytes(data, ea, range_end=max_ea, mask=mask, flags=flags)


def make_bytes_searcher(
    pattern: str,
) -> tuple[Callable[[int, int], int] | None, str | None]:
    tokens = pattern.strip().split()
    if not tokens:
        return None, "Empty pattern"

    normalized = " ".join("?" if t in ("??", "?") else t for t in tokens)

    def _search(ea: int, max_ea: int) -> int:
        return ida_bytes.find_bytes(normalized, ea, range_end=max_ea)

    return _search, None


# ============================================================================
# Type inference
# ============================================================================


def guess_tinfo(tif: ida_typeinf.tinfo_t, ea: int) -> bool:
    try:
        rc = ida_typeinf.guess_tinfo(tif, ea)
        if isinstance(rc, bool):
            if rc:
                return True
        elif int(rc) > 0:
            return True
    except Exception:
        pass

    return False


# ============================================================================
# UDM (struct/union member) access
# ============================================================================


def tinfo_get_udm(
    tif: ida_typeinf.tinfo_t, name: str
) -> tuple[int, ida_typeinf.udm_t | None]:
    """Return ``(index, member)`` for a named UDM, or ``(-1, None)``."""
    return tif.get_udm(name)
