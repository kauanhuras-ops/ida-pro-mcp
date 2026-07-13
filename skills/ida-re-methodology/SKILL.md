---
name: ida-re-methodology
description: Master workflow for productive reverse engineering of an IDA Pro database over MCP. Use at the start of ANY analysis session, or when deciding how to approach a binary, a subsystem, a function, or a cluster. Encodes decomp.me-style recompilation discipline (ground-truth against disassembly, iterate to fixpoint, name+type everything, confirm calling conventions and return types from the bytes). Routes to the focused skills: ida-function-recon, ida-cluster-analysis, ida-struct-recovery, ida-decomp-verify, ida-calling-convention.
---

# RE Methodology — the IDB Swiss-army knife

> ⚠️ **GROUND TRUTH — TRUST ONLY THE DISASSEMBLY, AND YOUR OWN EYES.** Never trust the decompiler
> output or existing comments. **Comments lie** — stale, wrong, or deliberately misleading. **The
> decompiler guesses, errs, and silently breaks.** The disassembly is the bytes the CPU actually
> executes; it never lies. Every name, type, prototype, struct field, and conclusion must trace back
> to instructions you read yourself in `disasm` / `insn_query`. Whenever pseudocode or a comment
> disagrees with the disassembly, the disassembly wins — every time.

## Set the goal first — `/goal`

Before touching the database, pin the session objective with the **`/goal`** command, and **re-issue
it whenever the target changes** so the active goal always reflects what you're working on right now:
`/goal reverse <target/subsystem>: name + type everything, confirm every convention/return from disasm`.
Every focused skill below re-sets `/goal` to its own concrete target on entry.

The goal of a session is a database where **every reachable function, parameter, global, and
structure is named and correctly typed, and every calling convention and return type is confirmed
against the disassembly**. This skill is the router and the discipline; the focused skills below do
the deep work.

## Prime directive: write to the IDB after every step, not at the end

The deliverable is **the modified database**, not your explanation of it. Analysis that lives only in
your reasoning is lost work — invisible to the next pass, the next agent, and the user. So:

- **Every step ends with a mutation.** The moment you understand *anything* — what a variable holds,
  what a function does, what a field is — commit it right then: `rename`, `set_type`, `set_comments`.
  Do not read three functions and then think; read one thing, write what you learned, move on.
- **Comments are the cheapest commit — use them constantly.** Understood one line but not the whole
  function? Drop a `set_comments` at that address *now*. Don't hold the insight in your head hoping to
  write a tidy summary later; you'll lose half of it.
- **Bias to action over exposition.** A turn that produced pages of reasoning and zero IDB changes is
  a failed turn (unless the function was already fully done). If you've been reading for more than a
  step without writing anything back, stop and commit what you already know.
- **Batch within a step, never across steps.** Group the mutations of *one* step into one call (all
  the locals you just decoded → one `rename`), but never defer a step's writes to a later "cleanup"
  pass. Small, frequent commits beat one big one.
- **Talk less, in the chat too.** Keep prose to a one-line note of what you just committed and what's
  next. The IDB edits are the progress; narrate them, don't replace them.

Rule of thumb: **understanding : mutations should trend 1:1.** Each thing you figure out should leave
a mark in the database in the same step you figured it out.

## The recompilation mindset (from decomp.me)

decomp.me works by writing C, compiling it, and diffing the produced assembly against the target
until they match byte-for-byte. You can't compile here, but you adopt the same loop against IDA's
own output:

1. **Disassembly is ground truth. Decompiler output AND existing comments are hypotheses.** Hex-Rays
   guesses conventions, argument counts, signedness, struct layout, and stack usage — and silently
   breaks. Pre-existing comments (from prior passes, other tools, or the original author) are just as
   untrustworthy: stale, wrong, or misleading. Never take either as fact; every claim is verified
   against the instructions you read yourself. When they disagree, the bytes win — see
   `ida-decomp-verify`.
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
   register/stack usage — see `ida-calling-convention`.
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

The loop is short and tight, and **it turns over many times per function** — each turn commits
something. It is not "one big read, then one big write."

```
one cheap recon call  →  [ understand one thing → COMMIT it (name/type/comment) ] × many  →  propagate  →  next target
```

The inner bracket is the whole game: a micro-cycle of understand-one-thing-then-write-it that repeats
until the function is done. Never let the bracket run more than once without a mutation.

### 0. Orient (once per session)
- `server_health` — confirm an IDB is loaded and ready.
- `survey_binary` — file metadata, segments, entry points, interesting strings/imports, call-graph
  summary, function classification. This is your map. Do it first, always.
- **Fresh/blank IDB?** Go to **ida-cold-start** first — finish auto-analysis, resolve library code,
  type imports, and seed targets before diving into any one function.
- Set a terse output format if you'll be doing high volume: `set_output_format`.

### 1. Choose a target and the right skill

| You want to… | Go to | Primary tools |
|---|---|---|
| Start from a fresh/blank IDB | **ida-cold-start** | `survey_binary`, `imports_query`, `find_regex` |
| Understand/finish ONE function | **ida-function-recon** | `analyze_function`, `decompile`, `disasm` |
| Understand a subsystem / group | **ida-cluster-analysis** | `callgraph`, `analyze_component`, `func_query` |
| Recover a struct/class/vtable | **ida-struct-recovery** | `read_struct`, `declare_type`, `set_op_type` |
| Decompiler output looks wrong | **ida-decomp-verify** | `disasm`, `decompile`, `insn_query` |
| Confirm convention/return type | **ida-calling-convention** | `disasm`, `insn_query`, `set_type` |
| Confirm real size/args/data by running | **ida-dynamic-verify** | `dbg_start`, `dbg_add_bp`, `dbg_read`, `dbg_regs_named` |

### 2. One recon call, then start writing
Take *one* cheap, high-signal read: `analyze_function` (single) or `analyze_component` (group) gives
pseudocode + strings + constants + callers + callees + xrefs at once. That is enough context to begin
committing — do **not** keep reading more functions "for context" before you've written anything back.
The one rule that gates a write: confirm the specific claim against the disassembly of the thing
you're changing (a name needs its evidence, a type needs its access width). Verify *that one claim*,
commit it, then verify the next.

### 3. Commit continuously as you understand
Every claim you confirm (a variable's meaning, a name, a type, a prototype, a struct field) is written
immediately with `rename` / `set_type` / `type_apply_batch` / `set_comments` / `declare_stack`. Batch
the writes that belong to the *same* moment of understanding into one call; don't accumulate findings
across the whole function to dump at the end. Use `diff_before_after` to *see* the pseudocode improve
as you commit — that visible improvement is the signal you're on track. If you've decoded a line but
can't fully name the function yet, the finding still gets written — as a comment, now.

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

- **Commit after every step; the IDB is the deliverable.** Never accumulate understanding across
  functions and defer the writes. If a step produced insight but no `rename`/`set_type`/`set_comments`,
  it isn't finished. A comment is always available as the minimum write.
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
