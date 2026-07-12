---
name: ida-function-recon
description: Deep, complete workup of a SINGLE function over IDA Pro MCP — from sub_XXXX to fully named, typed, and disassembly-verified. Use when the user points at one function ("what does sub_401000 do", "clean up this function", "type this properly"). Covers the recon→hypothesize→verify→commit→propagate loop, renaming locals/stack/globals, setting the prototype, and confirming every claim against the bytes. For convention/return-type specifics see ida-calling-convention; for struct fields see ida-struct-recovery; for pseudocode-vs-asm mismatches see ida-decomp-verify.
---

# Function recon — one function to fixpoint

> ⚠️ **GROUND TRUTH — TRUST ONLY THE DISASSEMBLY, AND YOUR OWN EYES.** Never trust the decompiler
> output or existing comments. **Comments lie** — stale, wrong, or deliberately misleading. **The
> decompiler guesses, errs, and silently breaks.** The disassembly is the bytes the CPU actually
> executes; it never lies. Every name, type, prototype, struct field, and conclusion must trace back
> to instructions you read yourself in `disasm` / `insn_query`. Whenever pseudocode or a comment
> disagrees with the disassembly, the disassembly wins — every time.

Convert a single function into a fully named, typed, verified unit. The steps below look sequential,
but in practice you **interleave reading and writing**: understand one thing, commit it, understand
the next. Do not run Steps 1–2 as a long read and save all the writes for Steps 3–4. The output of
this skill is IDB edits, not a mental model — if a pass over the function produced no rename, type,
or comment, you either finished it or you over-analyzed.

## Step 1 — One briefing read, then start committing

```
analyze_function(addr, include_asm=false)   # pseudocode + strings + constants + callers + callees + xrefs
```
This one call is your briefing — it's enough to start writing. Pull ground truth *as you need it for a
specific claim*, not all up front:
```
decompile(addr)          # current Hex-Rays hypothesis
disasm(addr)             # ground truth; paginate with offset/max_instructions for big funcs
stack_frame(addr)        # current stack layout & sizes
```
As you read, **write immediately**: the moment you understand a local, `rename` it; the moment you
grasp a block, drop a `set_comments` there. Don't finish reading the whole function before the first
edit. The mental model is a byproduct; the committed names/types/comments are the goal.

## Step 2 — Identify the function

Rank the evidence, strongest first:
1. **It's an import/thunk** → `imports_query` already has the real name+prototype. Done.
2. **Owned strings** → a format string, path, or message names it. `find(target=..., kind=strings)`
   or read them straight from `analyze_function` output.
3. **Callee fingerprint** → it calls `malloc`+`memcpy`+`free` in a pattern; a CRC table; a syscall
   number. `callees(addr)` + naming callees first often reveals the parent.
4. **Xref pattern** → called once from `main` right after arg parsing → likely `init`/`parse_args`.
   `xref_query({addr, direction:"to", include_fn:true})`.
5. **Constants** → magic numbers (`0x9E3779B9` golden ratio, `0x5F3759DF`, poly constants) fingerprint
   algorithms. `int_convert` to check candidate encodings; never eyeball hex.

Commit the name (or a `?`-hedged comment) only when the evidence is real:
```
rename({ func: { addr, name: "parse_config" } })
```

## Step 3 — Set the prototype (return + params + convention)

The prototype is the highest-leverage edit: it fixes rendering in *every* caller.

1. Confirm the **calling convention** and **return type** from disassembly — see `ida-calling-convention`.
   Don't accept Hex-Rays' guessed `__fastcall`/`int` blindly.
2. Confirm **argument count and types** from how each incoming register/stack slot is used before
   first write (width of access = size; sign of compare = signedness; dereference = pointer).
3. Apply:
```
set_type({ addr, signature: "int __fastcall parse_config(Config *cfg, const char *path)" })
force_recompile(addr)
```
Re-read `decompile(addr)`. Arguments should now render with your names/types. If an argument
vanished or a new one appeared, your count was wrong — reconcile against disasm.

## Step 4 — Name and type the internals

Work top-down through the pseudocode, turning noise into meaning. Batch aggressively.

- **Locals** (Hex-Rays `vN`): `rename({ local: [{func_addr, old:"v3", new:"len"}, ...] })`.
- **Stack vars** carrying real objects: `declare_stack({ items:[{addr, offset, name, ty}] })` to give
  them a type, or rename via `rename({ stack: [...] })`. Buffers, saved regs, and structs live here.
- **Types on locals**: `set_type({ addr, variable:"cfg", ty:"Config *" })` (kind auto-detected).
- **Globals** touched: `rename({ data:[{old,new}] })`, and type them with `make_data` or `set_type`.
- **Magic constants → enums/flags**: create the enum once with `enum_upsert`, then render the operand
  with `set_op_type({ items:[{addr, op_n, kind:"stroff"/"offset", ...}] })` or apply the enum type.
- **Struct accesses** (`*(a1 + 0x18)`): stop and go to `ida-struct-recovery`; then `set_op_type` with
  `kind:"stroff"` to make the operand render as `a1->field`.

After each meaningful batch: `force_recompile(addr)` and re-read. Names/types you just set should
collapse several lines of noise into one readable statement.

## Step 5 — Verify the whole function

- Diff a rename/type live to confirm impact: `diff_before_after(addr, action, action_args)`.
- Walk the disassembly once more (`disasm`) and check the pseudocode accounts for every branch, every
  call, and every memory access. Unexplained `disasm` lines = a decompiler gap → `ida-decomp-verify`.
- Confirm no `__int64`/`_QWORD`/`_DWORD` placeholders remain where a real type is known.
- Basic-block sanity for gnarly control flow: `basic_blocks(addr)`.

## Step 6 — Leave the trail and propagate

```
set_comments({ items:[{addr, comment:"parse_config: reads KEY=VALUE lines into Config"}] })
```
Then propagate: `force_recompile` on each caller (`xref_query direction:"to"`), re-read them — your
new prototype/name usually makes several callers instantly clearer, seeding the next targets.

**Fix-on-sight.** While working this function you will often prove an *earlier* commit wrong — a
callee you named last pass is clearly something else now that you see how it's used here, or a
prototype you set drops an argument this call site sets up. Fix it the instant you see it:
`rename`/`set_type` the offending symbol and `force_recompile` it and its neighbours. Do **not**
note it for later — the wrong name/type is actively corrupting the pseudocode you're reading right
now, and every function above it inherits the error.

## Fixpoint check

Re-run `analyze_function(addr)`. If a full pass produced **no** new name, type, or comment, this
function is done. Otherwise loop from Step 2 on whatever the pass surfaced.

## Common traps

- **Trusting Hex-Rays' argument count** — it drops unused params and invents spilled ones. Count from
  the register/stack reads in `disasm`.
- **`__int64` everywhere** — that's "unknown", not "64-bit int". Replace with the real type; it usually
  shrinks to `int`/pointer once you check the access width.
- **Signed vs unsigned** — decided by `jl/jg` (signed) vs `jb/ja` (unsigned) and `movsx` vs `movzx` in
  `disasm`/`insn_query`, not by the decompiler's default.
- **Renaming on a guess** — if you can't cite the evidence, comment it with `?` instead.
- **Reading without writing** — if you've read the whole function and made zero edits, you're hoarding
  findings in your head. Commit them now (names, types, or at minimum comments); understanding that
  isn't in the IDB doesn't count.
