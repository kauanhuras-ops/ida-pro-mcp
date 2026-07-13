---
name: ida-cluster-analysis
description: Analyze and cluster GROUPS of related functions over IDA Pro MCP — subsystems, modules, call trees, or functions sharing a struct/global. Use when the target is bigger than one function ("map out the networking code", "what's this whole call tree do", "group these functions", "find all functions touching g_state"). Covers discovering clusters (by call graph, by shared data, by string/import family), analyzing them together with analyze_component, and driving a group to fully-typed state in dependency order. For each individual function use ida-function-recon; for the shared struct use ida-struct-recovery.
---

# Cluster analysis — subsystems, not single functions

> ⚠️ **GROUND TRUTH — TRUST ONLY THE DISASSEMBLY, AND YOUR OWN EYES.** Never trust the decompiler
> output or existing comments. **Comments lie** — stale, wrong, or deliberately misleading. **The
> decompiler guesses, errs, and silently breaks.** The disassembly is the bytes the CPU actually
> executes; it never lies. Every name, type, prototype, struct field, and conclusion must trace back
> to instructions you read yourself in `disasm` / `insn_query`. Whenever pseudocode or a comment
> disagrees with the disassembly, the disassembly wins — every time.

## Set the goal — `/goal`

On entry, pin the objective with the **`/goal`** command, and re-issue it as you descend into members:
`/goal map & type the <name> cluster (leaves→roots), recover its shared struct/enum, name every function`.

A cluster is a set of functions that belong together: a call tree under one root, everything that
touches one global/struct, or a family sharing a string/import theme (all the `SSL_*` callers, all
the crypto). Analyze the cluster as a unit so shared types and names propagate across it at once.

## Step 1 — Discover the cluster

Pick the discovery axis that matches the question:

**By call graph (a subsystem under a root):**
```
callgraph(roots=["main"], max_depth=4)          # bounded call tree; roots + nodes + edges
callgraph(roots=["recv_packet"], max_depth=6)   # everything a handler reaches
```
Read it as a dependency graph. Leaves are primitives (type them first); roots are policy.

**By shared data (everything touching one global/struct):**
```
xref_query({ addr:"g_state", direction:"to", include_fn:true })   # functions referencing the global
xrefs_to_field(...)                                               # references to a specific struct field
```
The set of referencing functions IS the cluster that owns that data structure.

**By theme (string/import family):**
```
imports_query({ filter:"*SSL*" })          # then xref each import to its callers
find(target="socket,connect,bind", kind="refs")
func_query({ name_regex:"^(enc|dec)rypt" })
```

**By classification:** `survey_binary` already buckets functions (library/thunk/leaf/etc.) and
summarizes the call graph — use it to spot the big components before drilling in.

## Step 2 — Analyze the cluster together

```
analyze_component(addrs=[...])   # per-function summaries + INTERNAL call graph + SHARED strings/constants/data
```
This is the cluster analog of `analyze_function`. Read it for:
- **Internal call graph** — the dependency order you'll process in (leaves → roots).
- **Shared globals/structs** — the context object threaded through the cluster. This is almost always
  the single highest-value struct to recover (→ `ida-struct-recovery`).
- **Shared strings/constants** — protocol tags, opcodes, error codes → often a shared enum.
- **Entry/exit functions** — where the subsystem is called from and what it calls out to.

## Step 3 — Name the cluster's shared vocabulary first (and write it down as you go)

Before touching individual functions, fix what they all share — it propagates everywhere at once. Each
of these is a *commit*, made the moment you identify it, not notes for later:
1. **The shared struct/context** → `ida-struct-recovery`, then it renders in every member function.
2. **The shared enum/opcodes** → `enum_upsert` once; apply across the cluster.
3. **The shared globals** → `rename` + `set_type`/`make_data` once each.

Even while still mapping the cluster, commit as you learn: name each function the instant its role is
clear (one `rename` batch), and comment the cluster's entry points with what they do. Don't spend a
whole turn producing a call-graph description with zero IDB edits — the map should be laid down *in*
the database (names + comments), not just in your reasoning.

Then `force_recompile` the whole cluster (batch the addrs) and re-read `analyze_component`.

## Step 4 — Process functions in dependency order

Work **leaves → roots** using the internal call graph. Each leaf you finish (via `ida-function-recon`)
improves the rendering of everything above it, so roots get easier as you climb.

- Batch the mechanical parts across the whole cluster: one `rename` call for all func names, one
  `type_apply_batch` for all prototypes you're confident about.
- Re-`callgraph` / re-`analyze_component` after each layer to pick up propagated improvements.
- **Fix-on-sight across the cluster.** Climbing toward the roots routinely disproves an earlier
  member's name, prototype, or the shared struct/enum — a "callback" leaf turns out to be a
  comparator, a shared field you typed as `int` is dereferenced as a pointer two layers up. Correct
  it immediately (retype the struct once, `type_apply_batch` the prototype, `rename` the func) and
  re-`force_recompile` the cluster, *then* continue upward. A stale error in a leaf is amplified by
  every function above it, so deferring it makes the roots harder, not easier.

## Step 5 — Clustering when the grouping isn't given

If the user wants you to *find* the clusters (not analyze a known one), partition the function list:

1. `func_query` / `list_funcs` for the population (filter out library/thunk via `survey_binary`
   classification).
2. Build the call graph (`callgraph` from entry points, or `callees`/`xref_query` per function).
3. Group by:
   - **Connected components / call-tree dominators** — functions only reachable through one root form
     a module.
   - **Shared data ownership** — functions sharing the same globals/struct fields (`xref_query`,
     `xrefs_to_field`) belong together even without direct calls.
   - **Locality** — consecutive addresses in the same segment are usually the same translation unit.
   - **Theme** — shared string/import families.
4. Report the clusters with a name, member list, entry points, and the shared type/global that
   defines each. Persist the grouping as comments or a naming prefix (e.g. `net_*`, `cfg_*`) so the
   structure is visible in the IDB.

## Step 6 — Verify the cluster is coherent

- No function in the cluster still shows the shared struct as `*(a1 + N)` — the type should render
  everywhere (spot-check a few with `decompile`).
- The internal call graph has no surprise edges into unrelated subsystems (those signal a
  mis-assigned function — reassign it).
- Every entry point has a confirmed prototype (callers outside the cluster depend on it).

## Output

Deliver: the cluster's purpose, its member functions (named), its entry/exit points, the shared
struct/enum/globals you recovered, and the dependency order. Leave the IDB with a consistent naming
prefix per cluster so the partition is legible to the next pass.
