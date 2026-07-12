---
name: calling-convention
description: Confirm a function's calling convention, argument count/types, and return type from the DISASSEMBLY over IDA Pro MCP, instead of trusting Hex-Rays' guess. Use when setting a prototype, when arguments render wrong, when the return type is unclear, or as the mandatory confirmation step before committing any function signature. Covers reading argument registers/stack by ABI, detecting return-value width from the exit path, spotting variadic/struct-return/thiscall, and applying the confirmed prototype. Feeds function-recon (prototype step) and decomp-verify (phantom-argument fixes).
---

# Calling convention & return type — confirm from the bytes

A prototype is a claim about the ABI contract. Confirm every part of it against the disassembly before
`set_type`. This is the step that makes every caller render correctly, so getting it right pays off
across the whole database.

## Step 0 — Know the ABI in play

Check `survey_binary` for bitness/platform. The register order for arguments depends on it:

| ABI | Integer/pointer args (in order) | Return | Notes |
|---|---|---|---|
| **x86-64 System V** (Linux/macOS) | `rdi, rsi, rdx, rcx, r8, r9`, then stack | `rax` (+`rdx` for 128-bit) | floats in `xmm0..7` |
| **x86-64 Microsoft** (Windows) | `rcx, rdx, r8, r9`, then stack | `rax` | shadow space; floats in `xmm0..3`; by-position not by-class |
| **x86 cdecl/stdcall** | all on stack (`[esp+..]`) | `eax` (+`edx` for 64-bit) | stdcall callee-cleans (`ret N`) |
| **x86 fastcall/thiscall** | `ecx`(,`edx`) then stack; `this`→`ecx` | `eax` | thiscall = `this` in `ecx` |
| **ARM/AArch64** | `x0..x7` / `r0..r3` | `x0`/`r0` | — |

## Step 1 — Count and type the arguments

Read the function entry with `disasm` and find, for each candidate arg register/stack slot, whether it
is **read before it is written**. A register read before any write to it = an incoming argument.

```
disasm(addr)                                     # entry prologue + first uses
insn_query({ queries:[{ mnem:"mov", func: addr }] })   # scan reg/stack setup within the function (scope: func)
```
- **Argument count** = the highest ABI register (in order) that's read-before-write, plus any
  `[rsp+N]`/`[ebp+N]` stack slots read as incoming (above the return address). A gap (e.g. uses `rdi`
  and `rdx` but never `rsi`) usually still means 3 args — Hex-Rays may drop the unused middle one;
  the disasm tells the truth.
- **Argument type/size** per slot: the access **width** (`dword`/`qword`/`byte`), whether it's
  **dereferenced** (pointer → recurse), **sign-extended** (`movsx` ⇒ signed), or **passed straight to a
  known API** (inherit that parameter's type).
- **`this` pointer**: if the first integer arg is dereferenced at many constant offsets, it's a
  context/`this` (→ `struct-recovery`); on x86 in `ecx` it's `__thiscall`.

## Step 2 — Determine the return type

Inspect what the exit path leaves in the return register:
- Find `retn` and the instructions writing `rax`/`eax` (or `xmm0` for float) before it (`disasm`, or
  `insn_query mnem:"ret"` / writes to `rax`).
- **Width**: last write is to `al`→`char`/`bool`, `ax`→`short`, `eax`→`int`/`unsigned`, `rax`→64-bit
  or pointer. If `rax` is never meaningfully set before return and no caller reads the result → `void`.
- **Sign**: how callers use the result (`movsx`/signed compare ⇒ signed).
- **Pointer vs int**: returned value dereferenced by callers, or produced by `malloc`/`&`/`lea` ⇒
  pointer.
- **Struct-by-value return**: caller passes a hidden pointer in the first arg register (SysV: `rdi`
  holds the return slot, real args shift right; MS x64: `rcx`) and the function writes through it →
  return type is a struct, and every subsequent argument is off by one. This is a classic phantom-arg
  cause — check for it.
- **`__noreturn`**: function never returns (ends in `int3`, `ud2`, or a tail-call to abort/exit with no
  epilogue). Mark it — a wrong noreturn silently drops code in callers (→ `decomp-verify`).

## Step 3 — Detect the convention and specials

- **Callee stack cleanup** (`ret N` on x86) ⇒ `stdcall`/`thiscall`/`fastcall`; plain `ret` ⇒ `cdecl`.
- **Variadic**: mix of register args plus stack walking / `al` set to xmm count before calls (SysV) ⇒
  `...`. Give it the fixed prototype with a trailing `...`.
- **Register/nonstandard convention**: if args arrive in unusual registers (compiler-local or
  hand-written asm), use IDA's `__usercall`/`__spoiled` in the signature to pin exact registers.

## Step 4 — Apply and confirm propagation

```
set_type({ addr, signature: "int __fastcall parse(Ctx *this, const char *s, int len)" })
force_recompile(addr)
```
Then confirm the fix at the **call sites** — the highest-value verification:
```
xref_query({ addr, direction:"to", include_fn:true })   # every caller
# decompile a couple of callers: arguments should now line up with your prototype and disasm setup.
```
If a caller now shows a mismatched or dropped argument, your count/convention is still wrong — return
to Step 1 at that call site (the setup instructions before the `call` are ground truth).

## Confidence rules

- Convention/return set from disassembly = high confidence; commit it.
- Convention that only "looks right" in one caller = provisional; check a second caller before trusting.
- If truly ambiguous (e.g. tail-merged functions), set the best-supported prototype and leave a
  `set_comments` note stating what's unconfirmed. Never leave Hex-Rays' unverified guess in place while
  presenting it as fact.
