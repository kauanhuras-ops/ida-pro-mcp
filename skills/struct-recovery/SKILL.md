---
name: struct-recovery
description: Recover C structs, classes, vtables, and unions from disassembly over IDA Pro MCP, so that pointer arithmetic (*(a1 + 0x18)) renders as named field access (a1->count). Use whenever pseudocode is full of raw offset dereferences, when a context/this pointer is threaded through functions, or when the user asks to reconstruct a data structure. Covers deriving field offset/size/type from access widths in disasm, declaring the type, applying it, C++ vtable recovery, and verifying the layout round-trips. Pairs with cluster-analysis (find the struct's owners) and function-recon.
---

# Struct recovery — from `*(a1 + 0x18)` to `a1->count`

A struct is proven by how code accesses memory through a base pointer. Read the accesses, derive the
layout, declare the type, apply it, and the pointer arithmetic collapses into named fields everywhere.

## Step 1 — Find the base pointer and collect its accesses

Identify the pointer that's dereferenced at various constant offsets (the `this`/context/handle):
- In `decompile` output: the variable in `*(T *)(base + N)` / `base[N]` patterns.
- Collect every offset+width. `disasm`/`insn_query` give the *ground-truth* access width per site:
```
insn_query({ queries:[{ mnem:"mov", func: addr }] })   # find [reg+disp] accesses and their widths (scope: func)
disasm(addr)                                       # read displacement + operand size directly
```
The **operand size** at each `[base + N]` is the field size at offset `N`:
`byte ptr`→1, `word`→2, `dword`→4, `qword`→8. `movsx`/`movzx` tells you signed/unsigned. A `call
[base + N]` means offset `N` is a function pointer (vtable slot or callback).

## Step 2 — Derive the layout

Build an offset→(size, type, name) table from the evidence:
- Every observed offset is a field start. Gaps between observed offsets are unknown padding/fields —
  leave them as `char gapN[k]` so total size and later offsets stay correct.
- Type each field from its use: dereferenced further → pointer (recurse into a sub-struct); used in
  `movsx`+signed compare → signed int; passed to a known API → that API's parameter type; `call`
  through it → function pointer.
- Don't invent fields you didn't observe. Under-specifying (a gap) is safe; a wrong field shifts every
  later offset and corrupts the whole struct.
- Use `int_convert` for every offset/size — never hand-convert.

Cross-check what IDA already knows:
```
read_struct({ queries:[{ addr, struct? }] })   # auto-detects an existing/likely type at addr
search_structs(pattern="...")                  # is this struct already partially defined?
type_inspect({ queries:[{ name:"Config", include_members:true }] })
```

## Step 3 — Declare the type

```
declare_type(decls=[
  "struct Config { int magic; char gap4[4]; char *path; int count; void (*on_close)(Config *); };"
])
```
`declare_type` accepts full C, so declare interdependent structs together (forward-declare pointers).
For enums used as fields, `enum_upsert` first.

## Step 4 — Apply the type and make it propagate

Apply the struct type to the base pointer wherever it appears:
```
set_type({ addr, variable:"a1", ty:"Config *" })          # local/param in one function
type_apply_batch({ edits:[ {addr:f1, variable:"a1", ty:"Config *"}, {addr:f2, ...} ] })  # across the cluster
make_data({ items:[{ addr:"g_config", type:"Config", name:"g_config" }] })   # a global instance
force_recompile(addr)
```
For raw operands in the *disassembly* (struct member offset annotations, the GUI "T"/struct-offset):
```
set_op_type({ items:[{ addr:insnEA, op_n:1, kind:"stroff", struct:"Config", delta:0 }] })
```
Re-read `decompile`. `*(a1 + 0x18)` should now read `a1->count`. If it doesn't, the offset/size in
your declaration disagrees with the access width — fix the declaration, not the code.

## Step 5 — C++ vtables and classes

1. A struct whose **offset 0 is a pointer to an array of code pointers** is a polymorphic object; that
   array is the vtable.
2. Recover the vtable as its own struct of function pointers: read the pointer array (`get_bytes` /
   `read_struct`), each slot is a method — name them (`Class::method`) and set their prototypes with
   the object as `this` (first parameter, `__thiscall`/`__fastcall` per `calling-convention`).
3. Declare `struct Class_vtbl { ret (*method0)(Class *); ... };` and make the object's first field
   `Class_vtbl *vtbl`. Now virtual calls `(*(a1->vtbl->method3))(a1, ...)` render with names.
4. Constructors write the vtable pointer to offset 0 — use that to find every vtable and its class.

## Step 6 — Verify the layout round-trips

- `type_inspect({ queries:[{name:"Config", include_members:true}] })` — sizes/offsets match what you
  declared.
- `read_struct` a real instance in memory and sanity-check field values (pointers look like pointers,
  counts are plausible, strings resolve).
- Every member function of the struct now renders fields by name (spot-check via `decompile`).
- Total struct size matches allocation sites (`malloc(sizeof)` constant, or the stride of an array of
  these) — a mismatch means a missing/oversized field.

## Traps

- **Off-by-one offsets from wrong widths** — always take the width from `disasm`, not a guess.
- **Union confusion** — the same offset accessed as different types in mutually exclusive paths is a
  union, not a bug. Declare it as `union`.
- **Packing/alignment** — if declared offsets don't line up with observed ones, the struct is packed
  or has explicit padding; add `char gapN[k]` rather than fighting the compiler's alignment.
- **Shared struct, one owner named** — after recovery, apply it across ALL owners (see
  `cluster-analysis`), not just the function you were looking at.
