---
name: ida-calling-convention
description: Recover a function ABI contract from disassembly, call sites, and return use. Use when argument count, parameter types, calling convention, hidden arguments, or return type need proof.
hooks:
  Stop:
    - hooks:
        - type: prompt
          prompt: >-
            Decide whether Claude may stop the active ida-calling-convention task. Review
            $ARGUMENTS, especially last_assistant_message. Checklist: platform ABI;
            incoming locations and call sites; parameter types; return paths; hidden or
            special arguments; approved prototype read-back; open ABI doubt. Return
            {"ok": true} only if the message names the target and write scope and marks
            every checklist item pass or n/a with concrete evidence, with no required work
            left; or states a real blocker needing user input, approval, or external state
            and asks a direct question. Return {"ok": false, "reason": "the next concrete
            work"} for any missing, failed, unrun, or unsupported item.
          timeout: 30
          continueOnBlock: true
---

# Calling convention and return type

Target: IDA Professional 9.4 with ida-pro-mcp 3.4.0.

## Goal and stop contract

Before any IDA or MCP tool call, state a short working goal with target, scope, evidence,
and Done checks: recover the ABI contract of the named function in the requested read-only
or IDB-write mode; finish when used inputs, call-site arguments, return paths, hidden
arguments, and convention evidence agree.

Update the working goal when the target changes. Keep working until the done checks pass.
Do not apply a prototype in read-only mode.

Final audit: mark every hook checklist item `pass`, `n/a`, or `blocked` and give evidence.
The hook blocks a stop when any required item is unproved.

## Evidence rule

The current prototype and Hex-Rays argument list are hypotheses. Use the binary's
platform ABI, callee use, several call sites, return paths, and caller use together. One
register value at one call site is not enough to prove a parameter.

## 1. Identify the ABI

Use `survey_binary` for bitness, image base, segments, entries, and import clues. Its
`metadata.arch` field is only `32` or `64`; it does not name the processor, OS, or
compiler. Confirm those facts from the loaded file format, instruction set, imports,
symbols, and compiler patterns. Use the matching ABI, not a default from another platform.

| ABI | Common integer or pointer arguments | Common scalar return | Important notes |
|---|---|---|---|
| x86-64 System V | `RDI, RSI, RDX, RCX, R8, R9`, then stack | `RAX`; float in `XMM0` | FP args use `XMM0..7`; aggregate rules vary |
| Microsoft x64 | `RCX, RDX, R8, R9` by position, then stack | `RAX`; float in `XMM0` | shadow space; FP args use `XMM0..3` by position |
| x86 `cdecl` | stack | `EAX` or FP register | caller removes stack args |
| x86 `stdcall` | stack | `EAX` or FP register | callee normally removes fixed stack args |
| x86 fastcall or thiscall | compiler-specific registers plus stack | `EAX` or FP register | common forms use `ECX` or `EDX`, but check compiler and sites |
| AArch64 AAPCS64 | `X0..X7`; FP or vector in `V0..V7` | `X0` or `V0` | an indirect aggregate result commonly uses `X8` |
| ARM32 AAPCS | `R0..R3`, then stack | `R0` or FP register | alignment can consume or skip argument slots |

Small aggregate and vector rules have ABI-specific classification. Check the ABI rule for
the exact type before setting a prototype.

## 2. Find used incoming values

Read the function entry and all paths before each candidate input is replaced.

- A read-before-write supports that a location is an input used by this function.
- A prologue spill is still a read, but later use gives the type evidence.
- A missing read does not prove that the formal parameter does not exist.
- An unused trailing parameter may be impossible to recover from the callee alone.
- A gap between used registers does not by itself prove the full argument count.

Now inspect several call sites:

```text
xref_query({"queries":[{"addr":"<function>","direction":"to","xref_type":"code","include_fn":true}]})
```

For each site, map values set for the ABI locations before the call. Do not count a stale
register as an argument. Look for the same position and use across callers.

For stack arguments, account for the return address, saved frame data, alignment, and any
ABI shadow or home area. `disasm.asm.lines` is one newline-delimited string; page it with
`offset` and `max_instructions` when the function is large.

## 3. Infer parameter types

Use all uses of each position:

- access width gives the width used at that operation;
- a dereference supports a pointer;
- a known API parameter may give a stronger type;
- signed extension or comparison supports signed use;
- zero extension or unsigned comparison supports unsigned use;
- repeated constant offsets from a pointer support a struct or context candidate;
- a value used as a call target supports a function pointer.

An operation width does not always equal the source-language type. Compilers can narrow,
extend, or use only part of a value. Check callers and other uses before choosing the type.

## 4. Recover the return contract

Check every normal exit path and representative callers.

1. Find the last meaningful write to the ABI return location on each path.
2. Check whether callers read it and at what width.
3. Check whether callers dereference it, compare it, extend it, or ignore it.
4. Make sure all normal exits return compatible values.

Do not infer `void` only because one path does not set the return register. Do not infer
`bool` only from an `AL` or `EAX` write. Use caller behavior and value range.

For an aggregate return, check the exact ABI. A hidden result pointer is used only for
aggregates that the ABI returns in memory. System V x86-64 commonly shifts user arguments
after a hidden `RDI` pointer; Microsoft x64 commonly uses `RCX`; AAPCS64 commonly uses
`X8`. Small aggregates may return in registers.

Mark `noreturn` only when every reachable path fails to return and known tail targets also
do not return.

## 5. Check special forms

- Callee stack cleanup on x86 narrows the convention, but it does not alone distinguish
  every `stdcall`, fastcall, and thiscall form.
- A `this` pointer needs object-use evidence, not only its register.
- Variadic form needs fixed-argument evidence plus ABI-specific vararg behavior.
- Hand-written or compiler-local register use may need IDA `__usercall` syntax.
- Tail calls can hide the callee epilogue; check callers and the tail target.

If the function is a known Windows SDK, DirectX, or COM API, its published prototype already
gives the convention, argument types, and return type; take it one-to-one from
**ida-sdk-types** and confirm it against the call sites instead of re-deriving each part.

When static evidence remains load-bearing and unclear, use **ida-dynamic-verify** only
with explicit user approval. Live values can support a call for one run, but formal
parameters still need call and use evidence.

## 6. Apply and verify

In IDB-write mode, use `rename` if a new function name is needed and use `set_type` for the
prototype. They are separate operations. The type-only step has this shape:

```text
set_type({"edits":[{"kind":"function","addr":"<function>","ty":"int parse(struct Ctx *ctx, const char *text, int length)"}]})
force_recompile({"items":[{"addr":"<function>"}]})
```

If a checked rename and prototype both use the function address, they are independent and
may be sent in one general `batch`. Keep `force_recompile` after that batch because it
depends on the write results. A local rename followed by a type edit that uses the new
local name is dependent and must stay separate.

Read the callee and several callers again. Check that each rendered argument maps to the
same setup instructions and that return use is unchanged. If a known caller conflicts,
correct the prototype before moving on.
If a rename was also made, read back both the final name and prototype.

Do not apply an “almost right” certain prototype when an unknown parameter would change
argument positions. State the uncertainty or keep the safer current type.

## Done

Finish only when:

- the platform ABI is named;
- used incoming locations and representative call sites agree;
- parameter count limits and unused-parameter uncertainty are stated;
- each claimed parameter type has width and use evidence;
- all normal return paths and caller use support the return type;
- hidden results were checked for aggregate returns; `this` for member-style access;
  varargs for changing call-site counts; no-return behavior for paths without a return;
  and nonstandard registers when the platform ABI did not explain a live input;
- any approved prototype was recompiled and checked in the callee and callers.
