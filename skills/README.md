# IDA Pro MCP analysis skills — the Swiss-army knife

A cohesive skill suite for driving an IDA Pro database to a fully named, typed, and
disassembly-verified state over MCP. The discipline is borrowed from decomp.me-style
recompilation: **disassembly is ground truth, decompiler output is a hypothesis, iterate to a
fixpoint, and confirm every claim against the bytes.**

> ⚠️ **Trust only the disassembly, and your own eyes.** Comments lie; the decompiler guesses, errs,
> and silently breaks; the disassembly is the bytes the CPU runs and never lies. Every skill opens
> with this rule — when pseudocode or a comment disagrees with the disasm, the disasm wins.

Each skill also pins the current objective with the **`/goal`** command on entry and re-issues it as
the target sharpens. This requires your own `/goal` skill/command to be installed alongside these
(Claude Code only; Codex has no slash-command mechanism). If `/goal` isn't present the step is simply
skipped — the rest of the skill still works.

Skills auto-load from this directory (`skills/<name>/SKILL.md`). Start with `ida-re-methodology`; it
routes to the rest.

| Skill | Scope | Use when |
|---|---|---|
| **ida-re-methodology** | Master workflow & router | Any session start; deciding how to approach a binary/subsystem/function |
| **ida-cold-start** | Blank IDB → first targets | Fresh binary, nothing named yet, "where do I start" |
| **ida-function-recon** | One function → fully worked up | "What does this function do", "clean up / type this function" |
| **ida-cluster-analysis** | Groups of functions; clustering | "Map this subsystem", "group these functions", "what touches g_state" |
| **ida-struct-recovery** | Structs, classes, vtables, unions | Pseudocode full of `*(a1 + 0x18)`; a threaded context/`this` pointer |
| **ida-cpp-rtti** | C++ classes via constructors/RTTI/vtables | MSVC/GCC C++: vftable writes, virtual calls, mangled names |
| **ida-decomp-verify** | Find/fix decompiler errors vs disasm | Pseudocode looks wrong (phantom args, dropped code, `__int64` soup) |
| **ida-calling-convention** | Confirm convention + args + return type | Before committing any prototype; arguments render wrong |
| **ida-dynamic-verify** | Confirm facts by RUNNING it (debugger) | Real size/args/data/indirect targets you can't settle statically (unsafe, opt-in) |

### How they fit together

```
ida-re-methodology                    (survey → pick target → route → iterate → verify)
    ├── ida-cold-start                blank IDB: analysis → library code → imports → seed targets
    ├── ida-function-recon            single function loop
    │       ├── ida-calling-convention   confirm prototype from disasm
    │       ├── ida-struct-recovery      resolve *(base + N) into fields
    │       │       └── ida-cpp-rtti     C++: seed classes from ctors/RTTI/vtables
    │       └── ida-decomp-verify        QA the pseudocode against the bytes
    ├── ida-cluster-analysis          groups: discover → analyze_component → shared types → leaves→roots
    │       └── (reuses all of the above per member function)
    └── ida-dynamic-verify            run it: confirm real size/args/data, then persist to the IDB
```

### The invariant every skill upholds

Every reachable function, parameter, global, and structure ends up **named and correctly typed**, and
every **calling convention and return type is confirmed against the disassembly** — not left as an
unverified Hex-Rays guess. Uncertainty is recorded as a `?`-hedged comment, never baked into a
confident name.

And the database stays **internally consistent at all times**: the moment current work disproves an
earlier name, type, prototype, convention, or struct field, it is fixed *immediately* and
re-`force_recompile`d — never deferred. A stale error propagates into every downstream pass, so
correcting upstream mistakes on sight is part of the task, not cleanup for later.

**The deliverable is the modified database, not an explanation of it.** Every skill is action-first:
understand one thing, write it to the IDB (`rename` / `set_type` / `set_comments`) in the same step,
then move on. Comments are the cheapest commit and are always available. Analysis that never becomes
an IDB edit is lost work — a turn that produced lots of reasoning and zero database changes (on a
function that wasn't already done) is a failed turn.

### Companion skill

`ida-python/` documents the underlying IDAPython API (`ida_*` modules, `idautils`) for when a task
needs `py_eval`/`py_exec_file` beyond the structured MCP tools.
