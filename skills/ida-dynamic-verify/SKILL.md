---
name: ida-dynamic-verify
description: Confirm hard-to-settle facts by RUNNING the target under IDA's debugger over MCP — real struct sizes, real field layout and accessors, real argument values, real calling convention, real data/decrypted strings, and real indirect-call/vtable targets. Use when static analysis is ambiguous or expensive: a computed allocation size, a phantom-argument dispute, an indirect call you can't resolve, an encrypted blob, or a struct whose true extent you can't derive from disasm alone. Windows/native targets. The debugger EXECUTES the code — UNSAFE, opt-in, malware caution. Every runtime fact is written straight back into the static IDB. Pairs with ida-struct-recovery, ida-calling-convention, and ida-cold-start.
---

# Dynamic verify — run it to settle what the bytes alone can't

> ⚠️ **GROUND TRUTH — TRUST ONLY THE DISASSEMBLY, AND YOUR OWN EYES.** Never trust the decompiler
> output or existing comments. **Comments lie** — stale, wrong, or deliberately misleading. **The
> decompiler guesses, errs, and silently breaks.** The disassembly is the bytes the CPU actually
> executes; it never lies. Every name, type, prototype, struct field, and conclusion must trace back
> to instructions you read yourself in `disasm` / `insn_query`. Whenever pseudocode or a comment
> disagrees with the disassembly, the disassembly wins — every time.

The debugger extends "trust the bytes" to run time: registers and memory at a breakpoint are ground
truth in the same way instructions are. Use it to **confirm** a static hypothesis, never to replace
static reading. Static tells you *where* to look; the debugger tells you *what is actually there*.

## Set the goal — `/goal`

On entry, pin the objective with the **`/goal`** command, and re-issue it per question answered:
`/goal confirm at runtime: real sizeof(<struct>), real accessors of <ptr>, real args of <func>`.

> ⚠️ **UNSAFE — running executes the target.** Only debug when the user has opted into dynamic
> analysis. For unknown/malware samples this runs hostile code; assume network, persistence, and
> anti-debug. Set every breakpoint **before** `dbg_continue`. Debugger tools are marked unsafe for a
> reason — one question per run, then `dbg_exit`.

## Preconditions (do the static work first)

1. Form the static hypothesis you want to confirm (a candidate `sizeof`, an argument count, an
   indirect target). Debugging blind wastes runs.
2. Pick the **exact** addresses to break at (the allocation call site, the ambiguous `call`, the
   function entry). `disasm` them first.
3. Know your ABI (see `ida-calling-convention`) so you read the right registers.

## Core loop

```
dbg_start()                                  # launch the target, suspended
dbg_add_bp(addrs=["0x401230", "sub_401000"]) # code breakpoints (BPT_SOFT) at your sites
dbg_continue()                               # run to the first hit  (or dbg_run_to(addr) for a one-shot)
dbg_status()                                 # confirm suspended + current IP
# ...at the break, read ground truth:
dbg_regs_named(register_names="RCX, RDX, R8, RAX")   # arg/return registers (MS x64 shown)
dbg_read(regions=[{ addr:"0x...", size: 0x40 }])     # actual bytes at a pointer
dbg_stacktrace()                             # who called this, with module context
# ...confirm, then WRITE THE FINDING INTO THE STATIC IDB (below), then:
dbg_exit()                                   # clean up; don't leave the target running
```

Reads: `dbg_regs` / `dbg_gpregs` (full/GP set), `dbg_regs_named` (specific), `dbg_read` (memory).
Control: `dbg_run_to`, `dbg_step_over`, `dbg_step_into`, `dbg_continue`. Conditions:
`dbg_set_bp_condition(items=[{addr, condition, language:"python"}])` to stop only on the state you
care about instead of thousands of times.

## Techniques (what runtime settles that disasm can't)

**Real `sizeof` — break the allocator.** Put a BP on the allocation call site (or the app's own
allocator wrapper — see `ida-cold-start`). At entry the size arg is in the ABI slot (MS x64:
`HeapAlloc(heap, flags, size)` → size in `R8`; `malloc(size)` → `RCX`; `operator new(size)` → `RCX`).
`dbg_step_over` the call; `RAX` is the returned pointer. You now have the *real* size (even when it
was computed at runtime) and the object's address. Compare to your static guess and commit the type.

**Real field layout & accessors — hardware watchpoint.** `dbg_add_bp` only sets code breakpoints, so
for a memory write-watch on the fresh object use `py_eval`:
```python
import ida_dbg
ida_dbg.add_bpt(0x7ff6_0000_1000, 8, ida_dbg.BPT_WRITE)   # break on WRITE to this field/range
```
Continue; every hit is a real write — record offset (address − base), width, and value. This recovers
the true layout, including offsets and the **maximum offset ever touched = the real struct size**, and
catches accessors static xrefs miss (indirect/computed). Use `BPT_RDWR` to also catch reads.

**Real argument values / phantom-arg disputes.** Break at a call site, read the arg registers/stack:
are they real pointers, small ints, or dead? A register holding a valid pointer that disasm didn't
attribute to an argument settles the count/type dispute (feed the result back to `ida-decomp-verify`).

**Resolve indirect calls & vtables.** Break at `call [reg]` / `call [rax+N]`, read the target register
to get the concrete callee → name it and type the slot. Read the object's vtable pointer at runtime
(`dbg_read` at offset 0, then the slot array) to dump and name every virtual method.

**Real data — decrypted strings, parsed config, computed keys.** Break *after* the routine that
produces them and `dbg_read` the buffer to get plaintext/values, then annotate the static site with a
comment. This is how you recover string-decryption output and config the static view only shows as
noise.

**Real control flow & counts.** Which branch is actually taken with live data; real loop trip count;
real array element stride (watch the index register advance). Use conditional breakpoints to catch a
specific state.

## Reconcile — every runtime fact becomes a static edit (immediately)

The debug session is throwaway; the IDB is the deliverable. The moment runtime confirms something,
write it into the static database in the same step:
- confirmed size/layout → `declare_type` + apply (`ida-struct-recovery`);
- confirmed prototype/convention → `set_type` (`ida-calling-convention`);
- resolved indirect target / vtable slot → `rename` + prototype;
- decrypted string / real value → `set_comments` at the static address.

**Rebase runtime → static addresses first.** ASLR means runtime addresses differ from the IDB. Convert
via the module base (from `dbg_stacktrace` / the loaded module) with `int_convert` before naming
anything — a name applied at an un-rebased address lands in the wrong place.

## Cautions

- One question per run; set breakpoints before continuing; `dbg_exit` when done — don't leave the
  process live.
- Use `dbg_set_bp_condition` for hot sites (allocators fire constantly) so you stop only on the case
  you're investigating.
- Anti-debug is common on protected/malware targets; a clean static hypothesis first means fewer runs
  in a hostile process.
- Runtime confirms, it does not persist — if you didn't write the fact into the IDB, it's lost when
  the session ends.
