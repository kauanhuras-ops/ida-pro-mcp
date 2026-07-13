---
name: ida-cluster-analysis
description: Analyze a related group of functions over IDA Pro MCP. Use for a subsystem, call tree, shared-global group, or function family that is larger than one function.
hooks:
  Stop:
    - hooks:
        - type: prompt
          prompt: >-
            Decide whether Claude may stop the active ida-cluster-analysis task. Review
            $ARGUMENTS, especially last_assistant_message. Return {"ok": true} only if
            the message names the current user target and write scope, lists concrete
            evidence that all applicable Done checks passed, and says no required work
            remains; or if it states a real blocker that needs user input, approval, or
            external state and asks a direct question. Return {"ok": false, "reason":
            "the next concrete work"} for a progress-only report, TODOs, unchecked
            claims, failed or unrun checks, or unsupported completion.
          timeout: 30
          continueOnBlock: true
---

# Cluster analysis

## Goal and stop contract

Before any IDA or MCP tool call, set the working goal: map the named group in the
requested read-only or IDB-write mode; finish when members, boundaries, shared data,
entry and exit paths, and open gaps are checked.

Update the working goal when the member set or target changes. Keep working until the
done checks pass. Do not rename a group or its members when the request is read-only.

The frontmatter `Stop` hook checks the last response. Before a final response, include a
short completion audit with the target, write scope, checks run, results, and remaining
work. If required work remains, the hook blocks stopping and returns the next work.

## Evidence rule

Treat call graphs, decompiler output, current names, types, and comments as hypotheses.
Direct-call graphs miss callbacks and other indirect edges. Check important membership
and boundary claims in disassembly, registration sites, data xrefs, or approved runtime
evidence.

## 1. Build a candidate member set

Choose the axis that matches the task.

### Calls under a root

```text
callgraph({"roots":["<root>"],"max_depth":4})
```

Set a depth and node bound. A common utility called by the group is not always owned by
the group. An indirect target may be missing.

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

### Address locality

Nearby functions may come from one source unit, but link order, folding, and optimization
can break that relation. Use locality only as a weak clue.

## 2. Analyze the group

```text
analyze_component({"addrs":["<func1>","<func2>","<func3>"]})
```

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
2. Batch names or prototypes that come from the same checked model. For any entity you both
   rename and type, run the `rename` step before the type step; a type application does not
   reliably keep a name in IDA. Check that names survived.
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

- the member list has a stated reason for each included function;
- key excluded neighbors and common utilities are stated;
- entry, exit, direct, callback, and known indirect paths are mapped;
- shared types, globals, enums, and constants have evidence;
- each in-scope member meets the needed part of **ida-function-recon**;
- approved IDB changes were recompiled and checked as a group;
- unresolved indirect edges, weak members, and missing paths are listed.

The output is a checked group model, not only a call-graph picture.
