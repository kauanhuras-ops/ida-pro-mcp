---
name: re-methodology
description: Master workflow for productive reverse engineering of an IDA Pro database over MCP. Use at the start of ANY analysis session, or when deciding how to approach a binary, a subsystem, a function, or a cluster. Encodes decomp.me-style recompilation discipline (ground-truth against disassembly, iterate to fixpoint, name+type everything, confirm calling conventions and return types from the bytes). Routes to the focused skills: function-recon, cluster-analysis, struct-recovery, decomp-verify, calling-convention.
---

# RE Methodology — the IDB Swiss-army knife

The goal of a session is a database where **every reachable function, parameter, global, and
structure is named and correctly typed, and every calling convention and return type is confirmed
against the disassembly**. This skill is the router and the discipline; the focused skills below do
the deep work.

## The recompilation mindset (from decomp.me)

decomp.me works by writing C, compiling it, and diffing the produced assembly against the target
until they match byte-for-byte. You can't compile here, but you adopt the same loop against IDA's
own output:

1. **Disassembly is ground truth. Decompiler output is a hypothesis.** Hex-Rays guesses conventions,
   argument counts, signedness, struct layout, and stack usage. Every guess it makes is a claim you
   verify against the instructions. When they disagree, the bytes win — see `decomp-verify`.
2. **Iterate to a fixpoint.** One pass never converges. Name a callee → its callers' pseudocode
   changes → new names become obvious → re-decompile. Keep looping a function (and its neighbours)
   until a pass produces no new information. `force_recompile` after every type/name change that
   should propagate.
3. **Types propagate; exploit it.** Correctly typing one function's prototype fixes argument
   rendering in every caller. Correctly typing one struct fixes every `*(a1 + 0x18)` into
   `a1->field`. Always type the *most-referenced* thing first — the propagation does the rest.
4. **Confirm, don't guess.** A rename is a claim ("this is `malloc`"); back it with evidence
   (imports, string, xref pattern, prototype match). A type is a claim; back it with the access
   width and offset seen in disassembly. Convention and return type are claims; confirm from
   register/stack usage — see `calling-convention`.
5. **Leave a trail.** Every confirmed fact becomes a rename, a type, or a comment in the IDB so the
   next pass (and the next agent) starts from it. Uncertainty becomes a `?`-prefixed comment, not a
   silent guess baked into a name.
6. **Fix-on-sight — correct upstream mistakes immediately.** The moment new evidence contradicts an
   *earlier* commit — a callee you named `init` is clearly a destructor, a prototype you set drops an
   argument the current call site proves exists, a struct field's width is wrong, a convention was
   misjudged — **stop and fix it now**, then `force_recompile` the affected functions. Never leave a
   known-wrong name/type/convention in the IDB "to clean up later": every downstream pass builds on
   it, so a stale error propagates and multiplies. A correction is not a detour from the current task
   — it *is* the task, because the whole database must stay internally consistent. If a fix would be
   large or risky, do the minimal correct thing now (retype/rename/`?`-comment) rather than deferring
   the whole thing.

## Session loop

```
survey  →  pick target  →  recon  →  hypothesize  →  verify vs disasm  →  commit (name/type/comment)  →  propagate  →  repeat
```

### 0. Orient (once per session)
- `server_health` — confirm an IDB is loaded and ready.
- `survey_binary` — file metadata, segments, entry points, interesting strings/imports, call-graph
  summary, function classification. This is your map. Do it first, always.
- Set a terse output format if you'll be doing high volume: `set_output_format`.

### 1. Choose a target and the right skill

| You want to… | Go to | Primary tools |
|---|---|---|
| Understand/finish ONE function | **function-recon** | `analyze_function`, `decompile`, `disasm` |
| Understand a subsystem / group | **cluster-analysis** | `callgraph`, `analyze_component`, `func_query` |
| Recover a struct/class/vtable | **struct-recovery** | `read_struct`, `declare_type`, `set_op_type` |
| Decompiler output looks wrong | **decomp-verify** | `disasm`, `decompile`, `insn_query` |
| Confirm convention/return type | **calling-convention** | `disasm`, `insn_query`, `set_type` |

### 2. Recon before touching anything
Read-first. `analyze_function` (single) or `analyze_component` (group) gives pseudocode + strings +
constants + callers + callees + xrefs in one call. Cheap, high-signal, no mutation. Never rename or
retype before you've read the disassembly of the thing you're about to change.

### 3. Hypothesize → verify → commit
For each claim (name, prototype, struct field, convention), find its evidence in the disassembly,
then commit it with the mutating tool. Batch commits: `rename`, `set_type`/`type_apply_batch`,
`set_comments`, `declare_stack`. Use `diff_before_after` when you want to *see* the pseudocode
change a rename/type causes in the same call.

### 4. Propagate and re-check
After any prototype/type/struct change, `force_recompile` the function and its callers, then
re-read. A change that doesn't visibly improve a caller is suspect — re-examine.

## Prioritization (what to name/type first)

1. **Imports & thunks** — free ground truth. `imports_query` gives real prototypes; propagate them.
2. **String-anchored functions** — a function holding `"connect"`, a format string, or an assert
   filename usually self-identifies. `survey_binary` and `find` surface these.
3. **High-fan-in leaves** — a tiny function called from 200 sites is a primitive (allocator, lock,
   logger). Naming it clears noise everywhere. Find with `func_query` + `xref_query`.
4. **Widest-referenced structs** — the `this` pointer / context struct threaded through a subsystem.
5. **Everything reachable from an entry point / export**, breadth-first via `callgraph`.

## Non-negotiable rules

- **Never hand-convert hex/dec/signedness** — use `int_convert`. Off-by-a-conversion corrupts types.
- **Address anything by name once named** — tools accept `main` as readily as `0x401000`. Rename
  early so later calls are readable and stable across rebases.
- **Batch.** Every mutating tool takes a list. One `rename` call with 30 entries beats 30 calls.
- **Dry-run risky renames** — `rename` supports `dry_run` and `allow_overwrite`; validate collisions
  before committing a big batch.
- **`?` for uncertainty.** If confidence < high, encode it: comment `? guessed: recv loop` rather
  than renaming to `recv_loop` as if confirmed. A wrong confident name costs more than no name.
- **Fix upstream errors on sight, never defer them.** When current work reveals an earlier
  name/type/prototype/convention/struct is wrong, correct it immediately and `force_recompile` — do
  not add it to a "TODO later" list. Stale errors propagate into every downstream pass.
- **Debugger tools are unsafe** and out of scope for static passes; only use `dbg_*` when the user
  wants dynamic confirmation.

## Definition of done (per function)

A function is "done" when all of the following hold and are backed by disassembly:
- [ ] Named meaningfully (or `sub_*` kept with a comment explaining why it can't be named).
- [ ] Prototype set: return type + every parameter typed and named; convention confirmed.
- [ ] No unresolved `*(x + N)` in pseudocode that a struct would fix (or field left as a known gap).
- [ ] Stack variables named/typed where they carry meaning (`declare_stack`).
- [ ] All magic constants that are enums/flags rendered as such (`enum_upsert` + `set_op_type`).
- [ ] Callees at least identified (named or triaged), so the next pass has a clean call list.
- [ ] A one-line summary comment at the entry point.

Then move outward: its callers become better, its callees become the next targets.
