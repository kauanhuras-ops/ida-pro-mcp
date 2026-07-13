---
name: ida-cluster-analysis
description: Analyze a related group of functions over IDA Pro MCP. Use for a subsystem, call tree, shared-global group, or function family that is larger than one function.
hooks:
  Stop:
    - hooks:
        - type: prompt
          prompt: >-
            Decide whether Claude may stop the active ida-cluster-analysis task. Review
            $ARGUMENTS, especially last_assistant_message. Checklist: scope and graph
            bounds; member and exclusion reasons; entry, exit, and indirect paths; shared
            data; member checks; approved writes and group read-back; open edges. Return
            {"ok": true} only if the message names the target and write scope and marks
            every checklist item pass or n/a with concrete evidence, with no required work
            left; or states a real blocker needing user input, approval, or external state
            and asks a direct question. Return {"ok": false, "reason": "the next concrete
            work"} for any missing, failed, unrun, or unsupported item.
          timeout: 30
          continueOnBlock: true
---

# Cluster analysis

Target: IDA Professional 9.4 with ida-pro-mcp 3.4.0.

## Goal and stop contract

Before any IDA or MCP tool call, state a short working goal with target, write scope,
member rule, graph depth and node bounds, evidence, and Done checks: map the named group;
finish when bounded members, boundaries, shared data, entry and exit paths, and open gaps
are checked.

Update the working goal when the member set or target changes. Keep working until the
done checks pass. Do not rename a group or its members when the request is read-only.

Final audit: mark every hook checklist item `pass`, `n/a`, or `blocked` and give evidence.
The hook blocks a stop when any required item is unproved.

## Evidence rule

Treat call graphs, decompiler output, current names, types, and comments as hypotheses.
Direct-call graphs miss callbacks and other indirect edges. Check important membership
and boundary claims in disassembly, registration sites, data xrefs, or approved runtime
evidence.

## 1. Build a candidate member set

Choose the axis that matches the task.

### Calls under a root

```text
callgraph({"roots":["<root>"],"max_depth":4,"max_nodes":200,"max_edges":500})
```

Set depth, node, and edge bounds to fit the goal. A common utility called by the group is
not always owned by the group. An indirect target may be missing.

### Shared data

```text
xref_query({"queries":[{"addr":"g_state","direction":"to","include_fn":true}]})
xrefs_to_field({"queries":[{"struct":"State","field":"status"}]})
```

Functions that touch the same state are good candidates, but read-only observers and
generic helpers may sit outside the owner group.

### Shared imports, strings, or names

```text
imports_query({"queries":[{"filter":"*SSL*"}]})
find({"type":"string","targets":["socket","connect","bind"]})
func_query({"queries":[{"name_regex":"^(enc|dec)rypt"}]})
```

Follow xrefs from each result. A shared word is a clue, not proof of ownership.
`find` with `type:"string"` is a case-sensitive raw UTF-8 byte search. Use `find_regex`
when the task needs case-insensitive regex matching over the MCP string-list cache.

### Address locality

Nearby functions may come from one source unit, but link order, folding, and optimization
can break that relation. Use locality only as a weak clue.

## 2. Analyze the group

```text
analyze_component({"addrs":["<func1>","<func2>","<func3>"]})
```

Use this once for the bounded group. It already gives per-function summaries, the internal
direct-call graph, and shared data. Do not first make one `analyze_function` call for every
member. Use focused calls only for members with an open claim. For repeated calls to one
query tool, use its native list input; use general `batch` only for independent calls to
different tools.

Record:

- internal direct calls;
- entry functions called from outside;
- calls and data use outside the group;
- shared globals, types, strings, and constants;
- callback registration and indirect dispatch;
- strong reasons to include or exclude each member.

Split the set if one part has no meaningful call or data relation to the rest. Add a
member only with evidence.

## 3. Set work order

Process known leaves before their callers when that improves type propagation. For a
cycle, callback set, or mutually recursive group, work on the strongly connected group as
one unit. Do not force every graph into a strict leaves-to-roots order.

A useful order is:

1. external boundary prototypes;
2. common leaf helpers;
3. shared context types, enums, and globals;
4. callbacks and indirect targets;
5. entry and policy functions.

Use **ida-function-recon** for each member, **ida-struct-recovery** for shared layouts,
and **ida-calling-convention** for boundary prototypes. A group built around a known
Windows SDK, DirectX, or COM interface is a ready-made cluster: take its member prototypes
and shared structs one-to-one from **ida-sdk-types** (a COM interface and its methods form
one such group).

## 4. Record approved changes

In IDB-write mode:

1. Apply a shared type only after its offsets and widths have evidence.
2. Batch names or prototypes that come from the same checked model. Use `rename` for a new
   name and a type tool for a type; read both results back.
3. Call `force_recompile` for affected members.
4. Run `analyze_component` again and check that calls and shared data still agree.

Do not add a common name prefix only to make the group look clean. Use one when ownership
is supported and it matches the project's naming style. In read-only mode, give the group
map in the report and make no IDB change.

If a caller disproves a leaf name, prototype, field, or enum value, fix the in-scope fact
before using it in higher functions.

## 5. Check boundaries

For each entry or exit edge:

- check the target and call form in disassembly;
- check the prototype where it affects the boundary;
- note data passed across the boundary;
- state whether the other side is owned by this group, a common service, or unknown.

Do not call an edge “unrelated” only because its current name is different.

## Done

Finish only when:

- the member list follows the goal's stated admission rule and bounds;
- every checked boundary neighbor is included or excluded with a stated reason;
- entry, exit, direct, callback, and known indirect paths are mapped;
- shared types, globals, enums, and constants have evidence;
- each in-scope member meets the needed part of **ida-function-recon**;
- approved IDB changes were recompiled and checked as a group;
- unresolved indirect edges, weak members, and missing paths are listed.

The output is a checked group model, not only a call-graph picture.
