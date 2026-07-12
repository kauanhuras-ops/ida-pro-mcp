---
name: ida-decomp-verify
description: Find and fix places where Hex-Rays decompiler output is WRONG or misleading by cross-checking pseudocode against the ground-truth disassembly over IDA Pro MCP. Use when pseudocode looks suspicious (phantom/missing arguments, __int64 everywhere, weird casts, dropped code, wrong signedness, bogus control flow), or as a QA pass before trusting a function. Covers the systematic disasm-vs-pseudocode diff, the catalogue of common Hex-Rays failure modes and their fixes, and confirming the fix re-decompiles clean. Uses the same evidence as ida-calling-convention and ida-struct-recovery.
---

# Decomp-verify — the bytes win

Hex-Rays output is a hypothesis built on guessed prototypes, types, and stack layout. This skill is
the disciplined diff between that hypothesis and the disassembly, and the fix for each disagreement.
When pseudocode and disassembly disagree, the disassembly is right.

## The diff procedure

```
decompile(addr)     # the hypothesis
disasm(addr)        # ground truth (paginate large funcs with offset/max_instructions)
basic_blocks(addr)  # confirm control-flow shape matches the pseudocode's branches
```
Walk them in parallel. For each pseudocode statement, find the instructions that produce it. Flag
anything where:
- an instruction/branch/call in `disasm` has **no** counterpart in the pseudocode (dropped code), or
- a pseudocode element (argument, cast, variable) has **no** basis in `disasm` (invented), or
- the **width/sign** of an operation differs between the two.

**Fix and record as you go, not at the end.** Don't compile a long list of discrepancies and then act.
The instant you confirm one, either apply its fix (below) or, if it's genuinely a decompiler
limitation, `set_comments` the correct reading at that address right then. Each discrepancy resolved
is one commit; the verification pass should leave a trail of edits behind it, not a report.

`insn_query` is your scalpel for targeted checks across the function:
```
insn_query({ queries:[{ mnem:"call", func: addr }] })     # every call — check arg setup per site
insn_query({ queries:[{ mnem:"movsx", func: addr }] })    # sign-extensions the decompiler may hide
```

## Failure-mode catalogue (symptom → cause → fix)

**Phantom or missing arguments.** Pseudocode shows `f(a, b, c)` but disasm sets only `rcx, rdx`; or
shows `f(a)` but disasm also loads `r8`. → Wrong prototype on the callee. Confirm the real arg count
from register/stack setup at the call site, then `set_type` the callee's signature and
`force_recompile` both. See `ida-calling-convention`.

**`__int64` / `_QWORD` / `_DWORD` soup.** These are "unknown", not real types. → Type the variable
from its access width and use. Usually collapses to `int`, a pointer, or a struct field once typed.

**Wrong signedness.** Pseudocode uses `unsigned` where the code is signed (or vice-versa). → Check
`disasm`: `movsx`/`jl`/`jg`/`imul`/`idiv` ⇒ signed; `movzx`/`jb`/`ja`/`mul`/`div` ⇒ unsigned. Retype
the variable/return.

**Dropped or "optimized-away" code.** A whole block in `disasm` (often error paths, `__noreturn`
handlers, tail calls, or code after a mis-detected `return`) is absent from pseudocode. → Often a
wrong `__noreturn` attribute on a callee, or a bad function boundary. Fix the callee's noreturn flag
(`set_type`/prototype) or the function bounds (`define_func` / `undefine` + redefine), then recompile.

**Bogus casts / stack noise.** `*(_DWORD *)((char *)&v1 + 4)` and `HIDWORD(x)` everywhere. → Wrong
stack-variable sizes or a struct that should be declared. Fix the stack layout (`declare_stack`) or
recover the struct (`ida-struct-recovery`).

**Wrong control flow / jumptable.** Pseudocode `switch` has wrong/missing cases, or a loop is
mis-shaped. → Compare with `basic_blocks`; a mis-recovered jump table needs the table/operand typed
(`set_op_type kind:"offset"`) or the indirect jump's targets fixed. Re-analyze the region.

**Missing/extra function, or wrong bounds.** Code that should be its own function is inlined into a
neighbour, or a function runs past its real end. → `define_func` to create the missing function or fix
bounds; `undefine` bad data-as-code (or `define_code` raw bytes that should be code).

**Call through wrong convention.** Args look scrambled (right values, wrong parameters). → The callee's
convention is misdetected; confirm and set it (`ida-calling-convention`).

**Uninitialized-looking variable used before set.** Often a register live across a call that Hex-Rays
lost. → Check `disasm`; may need a prototype fix on the intervening call (clobber/return info).

## The fix loop

For each confirmed discrepancy:
1. Establish the ground truth from `disasm`/`insn_query` (width, sign, arg count, target, bounds).
2. Apply the minimal fix: prototype (`set_type`), type (`type_apply_batch`), struct
   (`ida-struct-recovery`), stack (`declare_stack`), bounds (`define_func`/`undefine`), or operand
   (`set_op_type`).
3. `force_recompile(addr)` (and affected callers/callees).
4. Re-`decompile` and re-diff. The specific discrepancy should be gone and nothing new broken.
5. If pseudocode still disagrees with unchanged disassembly, your fix was wrong — revert the claim and
   re-derive. Never "fix" by renaming to hide the confusion.

Very often the root cause lives in **another** function: the discrepancy here is produced by a wrong
prototype, type, or convention you (or a previous pass) committed on a callee/caller. When that's the
case, **fix that upstream symbol immediately** — retype/rename it and `force_recompile` it — rather
than patching a local symptom or noting it for later. The whole point of verification is to remove
the error at its source; a deferred upstream fix just re-breaks the next function that touches it.

## Distinguish decompiler bug from your mistake

- A genuine Hex-Rays limitation (rare) is stable across recompiles and matches disasm only under a
  specific reading; document it with a `set_comments` note and, if needed, the correct reading. Don't
  bake a wrong C into names.
- Most "decompiler errors" are missing information you haven't supplied yet (types, prototypes, struct,
  bounds). Supplying it fixes them. Assume this first.

## Done when

Every `disasm` instruction is accounted for in the pseudocode, every pseudocode element traces to real
instructions, widths/signs/arg-counts agree, and a fresh `force_recompile` + `decompile` reproduces the
clean output. Then the function is trustworthy enough to build callers on.
