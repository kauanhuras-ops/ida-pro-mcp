---
name: ida-verify-dynamic
description: Verify hard-to-know facts about a binary by running it under the IDA Pro debugger instead of guessing from decompilation. Use whenever a claim is about a REAL value that static analysis cannot pin down — actual struct size, field offsets, member access widths, allocation sizes, pointer targets, buffer contents, or any concrete runtime value. Turns an ambiguous decompiler hypothesis (unions, inlined allocators, padding, obfuscated layout) into ground truth by breaking at the right instruction and reading actual memory and registers. Pairs with /goal and the ida-goal-supervisor verifier.
---

# Dynamic verification with the IDA debugger

Static decompilation *guesses* layout. The debugger *shows* it. When you need
the truth about a size, an offset, an access width, a pointer, or a live value,
stop reasoning about pseudocode and go read the real bytes.

This is cheap and high-signal: one breakpoint at the right place answers a
question you could argue about statically for an hour.

## Prerequisites

- A **live IDA Pro session** (GUI), not headless `idalib` — the debugger needs
  a real process.
- A debugger selected and the target configured (Debugger → Select debugger;
  set executable path / args, or attach). If `dbg_start` fails, stop and tell
  the user to configure it — do not retry in a loop.
- The MCP server started with **`--unsafe`** (all `dbg_*` tools are unsafe).
- **Run untrusted samples in an isolated VM/sandbox.** Dynamic verification
  *executes the target*.

## The verification loop

1. **Hypothesis** — from static analysis (decompile / disasm), state the exact
   claim: "`sizeof == 0x48`", "field at `+0x10` is a pointer read as 8 bytes".
2. **Pick the evidence instruction** — the one place where the truth is visible:
   the allocator call site, the first write to a field, a dereference.
3. **Breakpoint + reach it** — `dbg_add_bp`, then `dbg_start` / `dbg_continue`
   / `dbg_run_to`. Use a **conditional** breakpoint to catch the interesting
   instance instead of the first of a thousand.
4. **Observe** — read registers and memory at that moment.
5. **Confirm or refute** — compare to the hypothesis. If they disagree, the
   debugger wins.
6. **Write it back** — apply the confirmed type (`set_type`/`declare_type`),
   `force_recompile`, so the IDB now reflects reality. Never leave a proven
   fact only in chat.

## Tool map

| Need | Tools |
|------|-------|
| Start / stop / resume | `dbg_start`, `dbg_exit`, `dbg_continue`, `dbg_run_to`, `dbg_step_into`, `dbg_step_over` |
| Breakpoints | `dbg_add_bp`, `dbg_delete_bp`, `dbg_toggle_bp`, `dbg_bps` |
| Conditional / instance-selective bp | `dbg_set_bp_condition` |
| Registers | `dbg_regs_named` (targeted), `dbg_gpregs`, `dbg_regs_all`, `dbg_regs` |
| Debuggee memory (raw) | `dbg_read`, `dbg_write` |
| Typed / interpreted reads at a live ptr | `read_struct`, `get_int`, `get_bytes`, `get_string` |
| Where am I / who called me | `dbg_status`, `dbg_stacktrace` |
| Base conversion (always) | `int_convert` |

## Recipes

### Prove a struct's real size (allocation ground truth)
The size passed to the allocator at a constant-size call site **is**
`sizeof(struct)` — no padding guesswork.
1. Find the allocation call site (see `ida-cold-start` for finding the app's
   allocator wrapper). Break on it.
2. On x64 Windows, the size is typically in `RCX` (`HeapAlloc` → 3rd arg `R8`;
   `malloc`/`operator new` → `RCX`; confirm the callee's convention). Read it:
   `dbg_regs_named("RCX, RDX, R8")`.
3. `dbg_step_over` the call, read `RAX` — the returned pointer. That pointer +
   the size is the exact extent of the object.

### Prove a field offset and access width
1. Break where the field is used. `dbg_step_into`/`dbg_step_over` to the
   deref instruction; `disasm` it to see the encoded width (`mov eax,[rbx+10h]`
   = 4-byte read at `+0x10`).
2. Confirm the value: `dbg_read` (or `get_int`) at `base + 0x10`. The access
   width in the instruction — not the decompiler's inferred type — is the truth.

### Discover layout by watching writes
To learn a fresh struct's fields, break right after allocation (you have `RAX`
= base), then single-step through the constructor/initializer and note every
`[base + off]` store and its width. The set of written offsets and widths *is*
the field list. Then `declare_type` from it.

### Read the real data in a live instance
After the object is populated, read it typed:
`read_struct({addr: "<live ptr>", struct: "MyStruct"})`, or raw bytes with
`dbg_read` / `get_bytes`, or follow a pointer field with another `dbg_read`.

### Catch the one instance you care about
`dbg_set_bp_condition` with e.g. `RCX == 0x1000` (size filter) or a pointer
match, so a hot allocator call breaks only for the case under investigation.

### Confirm a pointer chain / indirect target
Break at the indirect call/jump; read the target register with `dbg_regs_named`;
`dbg_stacktrace` for the call context; `dbg_read` to walk ptr→ptr→data.

## Guardrails

- **Do not trust a type you just applied.** `read_struct` echoes whatever type
  is set. Prove size/offset from the *raw* signal (allocation size arg,
  disassembly access width, raw `dbg_read`) before applying, then use
  `read_struct` only to sanity-check.
- **One sample can lie.** Confirm on a second instance or call site when the
  claim is load-bearing.
- **Reconcile, don't paper over.** If the debugger contradicts the decompiler,
  fix the IDB type and `force_recompile`; a corrected type usually improves
  every caller's pseudocode.
- Always tear down with `dbg_exit` when done (unless the user wants it live).
