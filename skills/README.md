# IDA Pro MCP analysis skills — the Swiss-army knife

A cohesive skill suite for driving an IDA Pro database to a fully named, typed, and
disassembly-verified state over MCP. The discipline is borrowed from decomp.me-style
recompilation: **disassembly is ground truth, decompiler output is a hypothesis, iterate to a
fixpoint, and confirm every claim against the bytes.**

Skills auto-load from this directory (`skills/<name>/SKILL.md`). Start with `re-methodology`; it
routes to the rest.

| Skill | Scope | Use when |
|---|---|---|
| **re-methodology** | Master workflow & router | Any session start; deciding how to approach a binary/subsystem/function |
| **function-recon** | One function → fully worked up | "What does this function do", "clean up / type this function" |
| **cluster-analysis** | Groups of functions; clustering | "Map this subsystem", "group these functions", "what touches g_state" |
| **struct-recovery** | Structs, classes, vtables, unions | Pseudocode full of `*(a1 + 0x18)`; a threaded context/`this` pointer |
| **decomp-verify** | Find/fix decompiler errors vs disasm | Pseudocode looks wrong (phantom args, dropped code, `__int64` soup) |
| **calling-convention** | Confirm convention + args + return type | Before committing any prototype; arguments render wrong |

### How they fit together

```
re-methodology                    (survey → pick target → route → iterate → verify)
    ├── function-recon            single function loop
    │       ├── calling-convention   confirm prototype from disasm
    │       ├── struct-recovery      resolve *(base + N) into fields
    │       └── decomp-verify        QA the pseudocode against the bytes
    └── cluster-analysis          groups: discover → analyze_component → shared types → leaves→roots
            └── (reuses all of the above per member function)
```

### The invariant every skill upholds

Every reachable function, parameter, global, and structure ends up **named and correctly typed**, and
every **calling convention and return type is confirmed against the disassembly** — not left as an
unverified Hex-Rays guess. Uncertainty is recorded as a `?`-hedged comment, never baked into a
confident name.

### Companion skill

`idapython/` documents the underlying IDAPython API (`ida_*` modules, `idautils`) for when a task
needs `py_eval`/`py_exec_file` beyond the structured MCP tools.
