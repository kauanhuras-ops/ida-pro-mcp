---
name: ida-calling-convention
description: Recover a function ABI contract from disassembly, call sites, and return use. Use when argument count, parameter types, calling convention, hidden arguments, or return type need proof.
hooks:
  Stop:
    - hooks:
        - type: prompt
          prompt: >-
            Decide whether Claude may stop the active ida-calling-convention task.
            Review $ARGUMENTS, especially last_assistant_message. Return {"ok": true}
            only if the message names the current user target and write scope, lists
            concrete evidence that all applicable Done checks passed, and says no
            required work remains; or if it states a real blocker that needs user input,
            approval, or external state and asks a direct question. Return {"ok": false,
            "reason": "the next concrete work"} for a progress-only report, TODOs,
            unchecked claims, failed or unrun checks, or unsupported completion.
          timeout: 30
          continueOnBlock: true
---

# Calling convention and return type

## Goal and stop contract

Before any IDA or MCP tool call, set the working goal: recover the ABI contract of the
named function in the requested read-only or IDB-write mode; finish when used inputs,
call-site arguments, return paths, hidden arguments, and convention evidence agree.

Update the working goal when the target changes. Keep working until the done checks pass.
Do not apply a prototype in read-only mode.

The frontmatter `Stop` hook checks the last response. Before a final response, include a
short completion audit with the target, write scope, checks run, results, and remaining
work. If required work remains, the hook blocks stopping and returns the next work.

## Evidence rule

The current prototype and Hex-Rays argument list are hypotheses. Use the binary's
platform ABI, callee use, several call sites, return paths, and caller use together. One
register value at one call site is not enough to prove a parameter.

## 1. Identify the ABI

Get architecture, bitness, OS, and compiler clues from `survey_binary` and file metadata.
Use the matching ABI, not a default from another platform.

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
xref_query({"queries":[{"addr":"<function>","direction":"to","include_fn":true}]})
```

For each site, map values set for the ABI locations before the call. Do not count a stale
register as an argument. Look for the same position and use across callers.

For stack arguments, account for the return address, saved frame data, alignment, and any
ABI shadow or home area.

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

When static evidence remains load-bearing and unclear, use **ida-dynamic-verify** only
with explicit user approval. Live values can support a call for one run, but formal
parameters still need call and use evidence.

## 6. Apply and verify

In IDB-write mode:

```text
set_type({"edits":[{"addr":"<function>","signature":"int parse(struct Ctx *ctx, const char *text, int length)"}]})
force_recompile({"items":[{"addr":"<function>"}]})
```

Read the callee and several callers again. Check that each rendered argument maps to the
same setup instructions and that return use is unchanged. If a known caller conflicts,
correct the prototype before moving on.

Do not apply an “almost right” certain prototype when an unknown parameter would change
argument positions. State the uncertainty or keep the safer current type.

## Done

Finish only when:

- the platform ABI is named;
- used incoming locations and representative call sites agree;
- parameter count limits and unused-parameter uncertainty are stated;
- each claimed parameter type has width and use evidence;
- all normal return paths and caller use support the return type;
- hidden results, `this`, varargs, no-return behavior, and nonstandard registers were
  checked where relevant;
- any approved prototype was recompiled and checked in the callee and callers.
