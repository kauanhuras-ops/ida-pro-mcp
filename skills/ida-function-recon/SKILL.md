---
name: ida-function-recon
description: Analyze one function over IDA Pro MCP. Use to explain its behavior or, when IDB changes are requested, give it supported names, types, comments, and a checked prototype.
hooks:
  Stop:
    - hooks:
        - type: prompt
          prompt: >-
            Decide whether Claude may stop the active ida-function-recon task. Review
            $ARGUMENTS, especially last_assistant_message. Checklist: role and side effects;
            callers, callees, branches, and data; ABI; approved writes and read-back;
            conflict check; unresolved paths; final analyze_function check. Return
            {"ok": true} only if the message names the target and write scope and marks
            every checklist item pass or n/a with concrete evidence, with no required work
            left; or states a real blocker needing user input, approval, or external state
            and asks a direct question. Return {"ok": false, "reason": "the next concrete
            work"} for any missing, failed, unrun, or unsupported item.
          timeout: 30
          continueOnBlock: true
---

# Function recon

Target: IDA Professional 9.4 with ida-pro-mcp 3.3.0.

## Goal and stop contract

Before any IDA or MCP tool call, state a short working goal with target, scope, evidence,
and Done checks: analyze the named function in the requested read-only or IDB-write mode;
finish when behavior, control flow, calls, data use, and prototype questions are checked
against disassembly.

Update the working goal if the target changes. Keep working until the done checks pass. A
request such as “what does this function do?” is read-only unless the user also asks for
IDB changes.

Final audit: mark every hook checklist item `pass`, `n/a`, or `blocked` and give evidence.
The hook blocks a stop when any required item is unproved.

## Evidence rule

Treat pseudocode, current names, types, and comments as hypotheses. Use disassembly and
raw bytes as the main static evidence. Check function bounds first if the listing or
pseudocode is incomplete.

## 1. Get one briefing

Start with:

```text
analyze_function({"addr":"<function>","include_asm":false})
```

Then get only the views needed for the next claim:

```text
decompile({"addr":"<function>"})
disasm({"addr":"<function>","offset":0,"max_instructions":5000})
stack_frame({"addrs":["<function>"]})
```

Page large disassembly results. Do not read unrelated functions for context before the
current function gives a reason to do so.

## 2. Identify behavior

Use evidence in this order:

1. an import, thunk, export, or known prototype;
2. owned strings and direct data xrefs;
3. calls to already known functions;
4. callers and registration sites;
5. constants and instruction patterns;
6. control flow and memory effects.

If this function is a Windows SDK, DirectX, or COM API (by import name, ordinal, GUID, or
COM slot), give it the real SDK name, prototype, and structs one-to-one — route to
**ida-sdk-types** — rather than a generic name.

Use the real `find` schema:

```text
find({"type":"string","targets":["<text>"]})
xref_query({"queries":[{"addr":"<function>","direction":"to","include_fn":true}]})
```

A string or one caller may suggest a role, but it may not prove the whole role. State the
strongest supported behavior and list any missing path.

In approved write mode, a function rename has this shape:

```text
rename({"batch":{"func":[{"addr":"<function>","name":"parse_config"}]}})
```

Use a certain name only when the evidence supports it. Otherwise keep the old name and,
if comments are in scope, add a `?` comment with the hypothesis.

## 3. Check the prototype

Use **ida-calling-convention** for the full ABI check. In this function:

1. Find incoming values that are read before replacement.
2. Check how each value is used and at what width.
3. Check multiple call sites. Callee code may not reveal unused or trailing parameters.
4. Check every return path and how callers use the return value.
5. Look for hidden return buffers, `this` pointers, variadic use, and nonstandard register
   use.

In write mode, use `rename` for a new function name and `set_type` for the prototype, then
recompile and read both facts back:

```text
set_type({"edits":[{"addr":"<function>","signature":"int parse_config(Config *cfg, const char *path)"}]})
force_recompile({"items":[{"addr":"<function>"}]})
```

Then inspect the function and representative callers. A cleaner decompile is useful, but
it is not proof by itself.

## 4. Check local and data meaning

Work through:

- local and stack variables with a real role;
- globals and pointed-to data;
- constant flags or enum values;
- base-plus-offset memory accesses;
- indirect calls and callback data.

For struct-like accesses, use **ida-struct-recovery**. For a pseudocode mismatch, use
**ida-decomp-verify**.

Approved write examples:

```text
rename({"batch":{"local":[{"func_addr":"<function>","old":"v3","new":"length"}]}})
declare_stack({"items":[{"addr":"<function>","offset":"-0x20","name":"buffer","ty":"char[32]"}]})
set_comments({"items":[{"addr":"<instruction>","comment":"Checks the parsed length before copy"}]})
```

Use `make_data` only when replacing or creating a data item is intended. It may replace an
existing item, so do not use it as a simple type hint.

When a local, global, or stack variable needs both facts, use explicit name and type
operations. If a local is renamed first, use its new name as the later type locator.
`declare_stack` and `make_data` may create a name and type together.

After a type or name change that affects pseudocode, call `force_recompile` and read the
result. Fix a known conflict before going on.

## 5. Verify semantics

Compare pseudocode with disassembly by effect, not one source line per instruction.
Compiler setup, spills, and address work may not appear as separate pseudocode.

Check:

- every call and indirect transfer;
- conditional branches and loop exits;
- memory reads and writes that affect behavior;
- signedness and width where they change meaning;
- error and no-return paths;
- function boundaries and jump-table targets.

Use `basic_blocks` when control flow is hard to see. Use `diff_before_after` only for an
approved mutation; it is an unsafe mutating helper.

## Done

Finish only when:

- the function's purpose and important side effects are stated with evidence;
- relevant callers, callees, branches, and data accesses are accounted for;
- the argument, return, and calling-convention evidence is stated, including uncertainty;
- approved names, types, stack declarations, and comments were read back after recompile;
- no known in-scope IDB fact conflicts with the disassembly;
- the report lists any unresolved path or ambiguous type.

Run one final `analyze_function` check. If it gives new in-scope evidence, continue the
loop instead of stopping.
