---
name: ida-cold-start
description: Establish a trustworthy analysis base from a brand-new / unanalyzed IDA database before deep reversing. Use at the start of any engagement on a fresh IDB, or when asked to "start clean", map an unknown binary, or find its internal dynamic data structures. Covers best-practice decompilation order (survey, real entry points, type propagation, evidence-based naming) and an allocation-site-driven method for discovering heap structures — with the corrections that make the naive "WinMain → malloc → big chunks" approach actually work. Windows-first. Pairs with ida-verify-dynamic and /goal.
---

# Cold start: build a base you can trust

A fresh IDB is a pile of bytes with optimistic auto-analysis on top. Deep
reversing on a shaky base wastes effort — wrong types poison every
decompilation downstream. Fix the foundation first, in the right order, because
types and names **propagate**.

## Order of operations (do not skip ahead)

1. **Triage in one call** — `survey_binary`. Returns metadata, segments, entry
   points, top strings/functions by xref, imports by category, call-graph
   summary. Do **not** hand-call `list_funcs` / `imports` / `find_regex` for
   triage; this is all of it.
2. **Find the *real* entry points** — not just `WinMain`. See the box below.
   Enumerate every entry: exports, TLS callbacks, and CRT init arrays
   (`_initterm`) — static initializers and TLS callbacks run **before**
   `WinMain` and are where globals and singletons are often born.
3. **Propagate types top-down** — this is the highest-leverage step. Apply
   correct prototypes to imports (WinAPI signatures carry rich types), fix
   calling conventions, and set argument/return types at call boundaries.
   Every corrected type flows into callers' pseudocode via `force_recompile`.
   Tools: `set_type`, `declare_type`, `infer_types`, `type_query`.
4. **Name from evidence, not vibes** — anchor names on strings, imports, and
   constants (`xref_query`, `search_text`, `trace_data_flow` from an
   interesting string/global). Rename with `rename`; record findings with
   `set_comments`. Never invent a name a xref can't justify.
5. **Discover dynamic structures** — the allocation-site method below.
6. **Verify the hard facts dynamically** — hand sizes/offsets/values to the
   `ida-verify-dynamic` skill (or wrap the whole thing in `/goal`). Static
   layout is a hypothesis until the debugger confirms it.

## Best-practice decompilation rules

- Wait for auto-analysis before trusting results (`ida_auto.auto_wait` in
  scripts).
- **Never convert number bases by hand** — use `int_convert`.
- Reference functions by **name / pattern / xref**, never hardcoded addresses.
- Fix pointer and array types explicitly — the decompiler's default `int` /
  `_DWORD` hides structure. A correct pointer type is what turns `*(a1 + 16)`
  into `a1->field`.
- When you correct a type, `force_recompile` and re-read; the improvement
  cascades to callers.
- Don't try to reason through obfuscated code — deobfuscate/clean first.

---

## Discovering internal dynamic structures via allocation sites

Allocation-site analysis is a genuinely strong technique: the size handed to an
allocator at a **constant-size** call site is `sizeof(struct)` directly — ground
truth you cannot get by staring at field accesses. Use it. But the naive
recipe ("disassemble WinMain → find `malloc` → look at big allocations") leaks
most of the real structures. Here is the corrected method.

### Critique of "WinMain → library alloc → big chunks"
Good instinct — allocation size is real evidence — but four leaks:

1. **`WinMain` is the wrong sole anchor.** CRT startup, TLS callbacks, and C++
   static constructors run *before* it and allocate many of the global
   singletons. And Windows GUI apps are **event-driven**: most interesting
   allocations happen in `WndProc`, message/command handlers, thread procs, and
   vtable methods reached *indirectly* — a forward walk from `WinMain`'s direct
   callees never reaches them. Anchor on **allocation sites globally**, then use
   `dbg_stacktrace` at runtime to learn who really calls them.
2. **"Library alloc function" is a moving target.** It's rarely just `malloc`.
   Expect `operator new`/`new[]`, `HeapAlloc`/`HeapReAlloc`, `LocalAlloc`/
   `GlobalAlloc`, `VirtualAlloc`, `CoTaskMemAlloc`. With a statically-linked CRT,
   `malloc` is inlined/wrapped, so you see a *wrapper*, not the import. Almost
   every real app routes allocations through **its own allocator wrapper** — a
   function that tail-calls `HeapAlloc`/`new`. **Find that wrapper first**
   (`imports` → `xref_query` the allocators → the common callee), and pivot on
   *it*; that is where all the app's sizes actually appear.
3. **Raw size is a weak ranker.** A big allocation is just as likely a byte
   buffer, image, or decompression scratch as a struct, and the *most*
   interesting structs (list nodes, headers) are often small. Classify the size
   argument instead:
   - **Constant** → a fixed struct; the constant **is** `sizeof`. (Best signal.)
   - **`n * elem`** (computed) → an array/vector; the **multiplicand `elem`** is
     the element struct size — more informative than the total.
   - **Opaque / fully variable** → probably a raw buffer, not a struct.
   Then rank by **how the returned pointer is used**: stored into a global or a
   parent field, and dereferenced at *consistent offsets*. Xref density on the
   pointer beats byte count every time.
4. **Size alone doesn't give layout.** Allocation size *bounds* the struct;
   what defines the fields is how the pointer is **dereferenced** — the offsets
   touched and the access widths. And static layout is exactly where inlining,
   unions, alignment/padding, and over-allocating allocators (header + payload)
   mislead you. So this method produces a **hypothesis**; confirm size and
   offsets with `ida-verify-dynamic` before committing the type.

### The method

1. **Identify the app's allocator wrappers.** `imports` → filter to allocators
   → `xref_query` each → the function(s) everyone calls through is the wrapper.
   Treat those + the raw allocators as your allocation-site set.
2. **Enumerate allocation sites** across the whole binary (`xref_query` /
   `callees` on the wrapper set), not just `WinMain`'s subtree.
3. **Classify each site's size arg** (constant / `n*elem` / opaque) by reading
   the call site (`decompile` / `disasm`). Keep constant and `n*elem` sites.
4. **Follow the returned pointer** (`trace_data_flow` forward): where is it
   stored, and at what offsets/widths is it later read/written? Those offsets
   and widths are the field list; the allocation size is the upper bound.
5. **Draft the type** with `declare_type` / `set_type`; sanity-check with
   `read_struct`; then `force_recompile` callers.
6. **Verify on a live process** — confirm the real size at the allocator return
   and the real offsets at first-write, per `ida-verify-dynamic`. Only then is
   the struct proven.

> On Windows we default to *not* second-guessing the Windows-only focus — the
> allocator set, calling conventions (`RCX/RDX/R8/R9`), and CRT/TLS entry
> behavior above are all specific to it.
