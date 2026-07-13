---
description: Run a verifiable reverse-engineering task under supervisor verification. The main agent executes; a supervisor sub-agent independently re-checks every claim against IDA MCP ground truth (preferring the debugger) before the goal is allowed to pass.
argument-hint: <verifiable task, e.g. "prove sizeof(GameState) and the offset of its entity array">
---

# /goal — supervised, verifiable RE

You are the **executor**. `$ARGUMENTS` is the goal. You do not get to declare
success; a **supervisor** sub-agent does, and only against evidence it re-derives
itself. Optimize for *provable* claims, not plausible ones.

Uses IDA Pro MCP. Debugger tools are `@unsafe` — the server must run with
`--unsafe` and against a **live IDA session** (not headless idalib) for any
dynamic step.

## 1. Turn the goal into an acceptance test

Before touching the binary, rewrite `$ARGUMENTS` into 1–5 **falsifiable
claims**, each with the concrete evidence that would confirm *or refute* it.
A claim is falsifiable only if it names an observable: an address, a size in
bytes, a field offset, an access width, a runtime value, a pointer target.

| Vague goal | Falsifiable claims |
|------------|--------------------|
| "understand the config struct" | `sizeof == 0x48`; field at `+0x10` is a `char*` read as 8 bytes; live instance at the ptr in `g_cfg` has `+0x0 == 0xC0DE` |
| "find how packets are parsed" | `sub_401000` is the dispatcher; it indexes a `handler[16]` table at `+0x8` of the session object; entry 3 = `sub_4020A0` |

If the goal cannot be made falsifiable, stop and say so — do not proceed on a
goal that has no failure condition.

## 2. Pick the method (bias to ground truth)

- **Fresh / unanalyzed IDB** → load the **`ida-cold-start`** skill first to
  establish a trustworthy base (real entry points, propagated types, named
  functions) before making any claim.
- **Any claim about real size, offset, access width, pointer target, or a
  runtime value** → load the **`ida-verify-dynamic`** skill and confirm it on
  a live process. Static decompilation is a *hypothesis generator* here, not
  evidence: inlined allocators, unions, padding, and obfuscation all make the
  pseudocode lie about layout.
- Never convert number bases by hand — use the `int_convert` tool.

## 3. Execute and keep an evidence ledger

For each claim, record a row: **claim → tool call(s) made → observed value →
verdict**. Cite addresses and raw values, not prose. Prefer a debugger
observation (`dbg_read`, `read_struct` at a live pointer, `dbg_regs_named`)
over a decompiler inference wherever the claim is about what actually happens
at runtime. When static and dynamic disagree, the debugger wins — then fix the
IDB (`set_type` / `declare_type`, `force_recompile`) so the decompilation
matches reality, and note the correction.

## 4. Hand off to the supervisor — do not self-certify

Launch the **`ida-goal-supervisor`** sub-agent (Task tool) with:
- the original goal,
- the falsifiable claims,
- your evidence ledger.

The supervisor re-derives each claim with its **own** MCP calls and returns
`PASS` or `FAIL` + specific gaps. Treat its ledger as untrusted until it says
otherwise.

## 5. Loop until PASS (cap 3 rounds)

On `FAIL`, address the named gaps — usually by gathering the missing dynamic
evidence — and re-verify. After 3 rounds without PASS, stop and report exactly
which claims remain unproven and why (e.g. "debugger not configured", "target
needs input to reach the allocation site"). An honest "unproven" beats a
confident guess.

## 6. Report

Final message = the verified claims with their evidence, any IDB changes you
made (renames, types, comments), and the supervisor's verdict. Tear down any
debug session with `dbg_exit` unless the user wants it left live.
