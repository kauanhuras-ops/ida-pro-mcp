---
name: ida-cold-start
description: Bring a FRESH, untouched IDA database to a productive state and pick the first high-leverage targets, over MCP. Use at the very beginning of a project — a binary just loaded, nothing named or typed yet, "where do I even start". Covers cold-start hygiene (finish auto-analysis, fingerprint the toolchain, detect packing), resolving and setting aside library code (FLIRT/Lumina), harvesting free ground truth (imports + strings), seeding entry points from BOTH code (entry/exports/callbacks) and data (allocation-site-driven struct discovery), and prioritizing. Then routes to ida-function-recon / ida-cluster-analysis / ida-struct-recovery / ida-dynamic-verify. Windows/native focused but general.
---

# Cold start — from a blank IDB to the first real targets

> ⚠️ **GROUND TRUTH — TRUST ONLY THE DISASSEMBLY, AND YOUR OWN EYES.** Never trust the decompiler
> output or existing comments. **Comments lie** — stale, wrong, or deliberately misleading. **The
> decompiler guesses, errs, and silently breaks.** The disassembly is the bytes the CPU actually
> executes; it never lies. Every name, type, prototype, struct field, and conclusion must trace back
> to instructions you read yourself in `disasm` / `insn_query`. Whenever pseudocode or a comment
> disagrees with the disassembly, the disassembly wins — every time.

The first hour decides the whole project. The decomp.me lesson applies: **don't reverse what you can
identify.** Resolve the library/CRT/STL, harvest the free ground truth (imports, strings), and only
then spend human-equivalent effort on the code that's actually the target.

## Set the goal — `/goal`

On entry, pin the objective with the **`/goal`** command:
`/goal cold-start <binary>: finish analysis, resolve library code, type imports, seed targets`.
Then re-set it to the first concrete target once you pick one.

## Step 1 — Hygiene: finish analysis and fingerprint the target

- `server_health` / `server_warmup` — ensure the IDB is loaded and **auto-analysis is complete**
  (`auto_wait`); reading a half-analyzed DB gives wrong xrefs and bounds.
- `survey_binary` — file metadata, bitness, segments, entry points, interesting strings/imports,
  call-graph summary, and a library/thunk/leaf function classification. This is your map; write down
  (as the goal / a comment) the toolchain: 32/64-bit, MSVC vs GCC/MinGW, static vs dynamic CRT.
- **Packing/obfuscation check.** Tiny import table + huge high-entropy section + a tail-jump into a
  writable segment = packed. If packed or heavily obfuscated (string encryption, import hashing,
  control-flow flattening), **stop** — unpack/deobfuscate first; naming a packed image is wasted work.
  Say so and treat it as a separate prerequisite, out of scope for this skill.

## Step 2 — Resolve and set aside library code (biggest time-saver)

Library code (CRT, STL, statically-linked OSS) is noise you must not hand-reverse:
- `survey_binary` already flags functions that carry a FLIRT signature as `library`.
- Apply more signatures where available (FLIRT/Lumina) via `py_eval` (`ida_funcs`/Lumina) so the
  bulk of runtime glue is named and greyed out.
- Result: the remaining un-named, non-library functions are the actual target surface. Everything
  below focuses only on those.

## Step 3 — Harvest free ground truth (imports + strings)

- **Imports carry real prototypes.** `imports_query` → for each, the OS/library prototype is known;
  applying it types every call site for free and propagates argument names outward. Do this in bulk
  first — it is the highest return-per-effort action in the whole project.
- **Strings anchor functions.** `find_regex` / `find` to index them; a function owning a format
  string, a path, an error message, or an assert filename usually self-identifies. Rename/comment
  those functions immediately.

## Step 4 — Seed targets from BOTH ends (not just top-down)

Real programs are not one call tree. Seed from all of:

**Code, top-down:** the real entry point, all exports, `WinMain`/`main`, and — critically —
**callback-reached code the call graph misses**: window procedures (xrefs to `RegisterClass*` /
`SetWindowLongPtr`), dialog procs, thread routines (`CreateThread`), TLS callbacks, COM vtable
methods, and callback-taking APIs (`EnumWindows`, `qsort`). Find these by xref'ing the relevant
imports and treating each callback argument as a root (`ida-cluster-analysis`).

**Data, bottom-up:** allocation-site-driven struct discovery — Step 5.

## Step 5 — Allocation-driven struct discovery (your idea, refined)

The instinct — *find the allocators, look at their callers, big allocations are internal structures* —
is one of the strongest signals in the binary. Here it is, sharpened, with the traps called out.

**Do this:**
1. **Map the whole allocator chain, including the app's own wrapper.** `malloc`/`operator new` →
   `_malloc_base` → `HeapAlloc` → `RtlAllocateHeap`. Also `VirtualAlloc`, `LocalAlloc`/`GlobalAlloc`,
   `CoTaskMemAlloc`, `SysAllocString`, `calloc`, `realloc`. With a **static CRT** (common on MSVC),
   `malloc` is not an import — identify it internally (it calls `HeapAlloc`, or via FLIRT). Apps
   usually wrap their own pool/arena allocator around `HeapAlloc`; **find that wrapper and pivot to
   its callers** — that's where the meaningful sizes live.
2. **Enumerate every allocation call site and read the size argument.** `xref_query` to the allocator,
   then at each site read the instruction feeding the size register (`disasm`/`insn_query`). A
   **constant** size is `sizeof(struct)` handed to you for free. Cluster sites by size → each distinct
   constant is a candidate type. Use `int_convert`, never eyeball the hex.
3. **Follow each allocation to its accessors.** Track the returned pointer (stored to a global? a
   field of a parent struct? returned?) and collect the functions that dereference it. That set is the
   struct's owner cluster → recover the layout with `ida-struct-recovery` and apply it across all of
   them.
4. **Prefer C++ constructors as seeds (MSVC/Windows).** `operator new(sizeof)` immediately followed by
   a ctor that writes a vftable pointer at offset 0 gives you size + fields + (via RTTI) often the real
   class name in one place. `new[]` stores element count in a header. Seed struct recovery from ctors.

**Critique — where the naive version misleads, and the fix:**
- **"Walk down from WinMain" misses most code.** In event-driven Windows apps WinMain is often just
  CRT glue + a message loop; the real logic runs in callbacks not reachable from it. → Seed from
  callbacks and exports too (Step 4), not only WinMain. (Per your scope, the Windows focus itself is a
  given — not critiqued.)
- **Size is frequently not constant.** `malloc(n * elem)`, `malloc(size + header)`, `realloc`. → Read
  the *computation* feeding the size arg: an `imul reg, N` before the call means "array of N-byte
  elements"; `calloc(count, size)` splits it for you. Constant-size sites are the easy wins; label the
  rest as arrays/variable and confirm dynamically.
- **Big ≠ struct.** A large allocation may be an I/O/decompression buffer, a bitmap, a string/lookup
  table, or an arena block holding many small objects. → Classify by *access pattern* in the disasm:
  fixed distinct offsets → struct; constant-stride indexing → array; sequential byte streaming →
  buffer. Size alone proves nothing.
- **Static can't confirm real size/count/contents.** The size heuristic is a hypothesis; a
  `HeapAlloc(h, f, computed_size)` yields nothing statically. → Confirm with **`ida-dynamic-verify`**:
  break the allocator, read the real size + returned pointer, and watchpoint the object to see which
  offsets are actually written (max offset = real size). This is where dynamic analysis is "simple and
  maximally effective," exactly as intended.
- **It's one axis.** Allocation-driven discovery is strongest for *structs*; import/string anchoring is
  strongest for *function identity*. Run both and let them meet in the middle — don't rely on the
  allocator walk alone for coverage.

## Step 6 — Prioritize and route

Order the target surface by leverage and hand each to its skill:
1. Imports & thunks already typed (Step 3) → propagate.
2. Distinct allocation sizes → **ida-struct-recovery** (seed the context/state structs first).
3. High-fan-in leaves (primitives called everywhere) → **ida-function-recon**.
4. Entry/export/callback roots → **ida-cluster-analysis** (breadth-first).
5. Anything ambiguous or computed → **ida-dynamic-verify**.

Persist as you go: every identified library func, typed import, named string-owner, and candidate
struct size is committed (`rename`/`set_type`/`declare_type`/`set_comments`) in the step you find it —
the cold-start pass should leave the DB visibly transformed, not just a plan in your head.
