---
name: ida-function-recon
description: Analyze one function over IDA Pro MCP. Use to explain its behavior or, when IDB changes are requested, give it supported names, types, comments, and a checked prototype.
hooks:
  Stop:
    - hooks:
        - type: prompt
          prompt: >-
            Decide whether Claude may stop the active ida-function-recon task. Review
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

# Function recon

## Goal and stop contract

Before any IDA or MCP tool call, set the working goal: analyze the named function in the
requested read-only or IDB-write mode; finish when behavior, control flow, calls, data
use, and prototype questions are checked against disassembly.

Update the working goal if the target changes. Keep working until the done checks pass. A
request such as “what does this function do?” is read-only unless the user also asks for
IDB changes.

The frontmatter `Stop` hook checks the last response. Before a final response, include a
short completion audit with the target, write scope, checks run, results, and remaining
work. If required work remains, the hook blocks stopping and returns the next work.

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

In write mode, apply a supported prototype and recompile:

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
