---
name: ida-re-methodology
description: Main workflow and router for evidence-based IDA Pro analysis over MCP. Use at the start of a task to set scope, choose a focused skill, verify claims, and define clear done checks.
hooks:
  Stop:
    - hooks:
        - type: prompt
          prompt: >-
            Decide whether Claude may stop the active ida-re-methodology task. Review
            $ARGUMENTS, especially last_assistant_message. Checklist: exact target and
            scope; every goal item; evidence for each claim; debug-string naming evidence;
            approved writes and read-back; conflict check; uncertainty and final report.
            Return {"ok": true} only if the
            message names the target and write scope and marks every checklist item pass or
            n/a with concrete evidence, with no required work left; or states a real
            blocker needing user input, approval, or external state and asks a direct
            question. Return {"ok": false, "reason": "the next concrete work"} for any
            missing, failed, unrun, or unsupported item.
          timeout: 30
          continueOnBlock: true
---

# RE methodology

Target: IDA Professional 9.4 with ida-pro-mcp 3.4.0.

## Goal and stop contract

Before any IDA or MCP tool call, state a working goal that names:

- the exact binary, subsystem, function, or data type;
- whether IDB changes are allowed;
- the evidence needed;
- the checks that prove the work is done.

Update the working goal when the target or write scope changes. Do not stop at a list of
possible findings. Keep working until the goal checks pass. Stop only when a missing
target, tool, user choice, or write or execution approval blocks safe work; state the
exact blocker and ask a direct question.

Final audit: mark every hook checklist item `pass`, `n/a`, or `blocked` and give evidence.
The hook blocks a stop when any required item is unproved.

If the user only asks for an explanation, review, or diagnosis, use read-only mode. Do not
change the IDB without a request that allows it.

## Evidence rule

Treat decompiler output, auto-analysis, names, types, and comments as hypotheses. Use
disassembly and raw bytes as the main static evidence. If function bounds, code/data
classification, or decoding look wrong, verify or repair them before using the listing.
Runtime evidence applies to the observed run and input only.

Debug and diagnostic strings are naming evidence. When a string is tied to the same code
or value by an xref, call argument, or data flow and exposes an original function, method,
parameter, local, field, or global identifier, use its exact spelling instead of inventing
a name and record the string address. State any ambiguity or conflict.

## Start and route

1. Call `server_health` and check `auto_analysis_ready`. This tool reports state; it does
   not wait. If the value is false, wait and check again before using analysis results.
2. Call `survey_binary` once for the first map. Do not repeat separate full-list calls for
   the same survey data. Its `metadata.arch` value is bitness (`32` or `64`), not a CPU
   name; get processor, file-format, OS, and compiler claims from separate evidence.
3. Set the target and route it:

| Need | Skill | Main tools |
|---|---|---|
| Fresh or weak IDB | **ida-cold-start** | `survey_binary`, `imports_query` |
| One function | **ida-function-recon** | `analyze_function`, `disasm` |
| Related function group | **ida-cluster-analysis** | `callgraph`, `analyze_component` |
| Struct, class, union, or vtable | **ida-struct-recovery** | `read_struct`, `declare_type` |
| C++ classes from RTTI or constructors | **ida-cpp-rtti** | `find_regex`, `xref_query`, `declare_type` |
| Windows SDK, DirectX, or COM API | **ida-sdk-types** | `imports_query`, `find_bytes`, `declare_type` |
| Pseudocode check | **ida-decomp-verify** | `decompile`, `disasm`, `basic_blocks` |
| ABI or prototype | **ida-calling-convention** | `disasm`, `xref_query`, `set_type` |
| Runtime fact | **ida-dynamic-verify** | `dbg_start`, `dbg_add_bp`, `dbg_read` |

Debugger work needs clear user approval. Do not route to dynamic work only because static
work is slow.

## Work loop

Use this loop on each in-scope item:

1. **Read:** get one useful view. For one function, start with `analyze_function`. It
   already gives a capped decompile, callers, callees, xrefs, strings, constants, and a
   block summary; do not request those views again unless a claim needs more detail. For a
   group, start with `analyze_component`.
2. **State one claim:** for example, a function role, parameter type, field offset, or
   branch meaning.
3. **Check it:** find the disassembly, raw bytes, xrefs, ABI rule, or approved runtime
   observation that supports or rejects the claim.
4. **Record it:** in read-only mode, keep it for the report. In IDB-write mode, apply the
   smallest supported `rename`, `set_type`, `declare_type`, or `set_comments` change.
   Do not turn an uncertain idea into a certain name. Use a name tool and a type tool when
   both facts are needed.
5. **Propagate:** after a type, prototype, or struct change, call `force_recompile` for
   affected functions and inspect the changed output.
6. **Recheck:** if the change creates a mismatch, correct or remove the claim before
   moving on.

Batch writes that come from the same evidence. Do not collect unrelated changes into one
large batch. Use `rename` with `dry_run` for a large or collision-prone rename.
Use a tool's native list input when all items use that tool. Use `batch` when two or more
different tool calls do not need an earlier result. Keep dependent calls separate so each
result is checked before the next call. `batch` may run normal writes, but it will reject
debugger, Python, hidden-extension, and other `MCP_UNSAFE` tools.
`disasm.asm.lines` is one newline-delimited string for token economy. Page it with
`offset` and `max_instructions`; do not request or rebuild an object per instruction.

**Name and type with the right operation.** `rename` creates a new name. `set_type` and
`type_apply_batch` apply types. In the preferred schema, every type edit has `kind` and
`ty`. Use `addr` for a function, local, or stack owner, `variable` for an existing local,
and `name` only for an existing global or stack-member locator. If a local is renamed
first, use the new name as the later locator. Read the final name and type back.
`declare_stack` and `make_data` may create both in one call.

## Work order

Prefer facts that improve many later views:

1. imports and thunks with known prototypes, including Windows SDK, DirectX, and COM APIs
   given their real one-to-one types (route to `ida-sdk-types`);
2. real entry points and exports;
3. string- or constant-anchored functions;
4. high-use leaf functions;
5. shared context types and globals;
6. callers and higher-level policy code.

This is a guide, not a reason to leave the user's target. Keep the goal scope fixed.

## Accuracy rules

- Use `int_convert` when a base, sign, or width conversion matters.
- Use symbol names after they are known; do not put fixed image addresses into reusable
  steps.
- Check calling conventions and return use at both the callee and call sites.
- Mark uncertainty in the report. In write mode, a `?` comment is allowed only when it
  helps the in-scope IDB work.
- Fix a known in-scope conflict before building more claims on it.
- Do not alter unrelated names, types, comments, code, or formatting.

## Done

Finish only when all goal checks pass:

- every item named by the goal was checked;
- each in-scope debug-string identifier was used exactly, or any ambiguity or conflict was
  stated, with the string address;
- each reported claim has stated evidence;
- all approved IDB changes were recompiled and read back;
- no known in-scope name, type, prototype, field, or comment conflicts with the evidence;
- open uncertainty and any out-of-scope design smell are stated;
- the final report says what was read, what changed, and what remains.

The scope is the target in the working goal. It is not every function reachable in the whole binary
unless the user asked for that full scope.
