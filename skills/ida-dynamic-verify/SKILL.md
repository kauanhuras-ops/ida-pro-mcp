---
name: ida-dynamic-verify
description: Verify one hard static-analysis claim with the IDA debugger. Use only after explicit approval to execute the target in a suitable environment.
hooks:
  Stop:
    - hooks:
        - type: prompt
          prompt: >-
            Decide whether Claude may stop the active ida-dynamic-verify task. Review
            $ARGUMENTS, especially last_assistant_message. Checklist: execution approval
            and run context; static hypothesis and live result; observation limits;
            address rebase; approved IDB writes and read-back; debuggee state; final
            verdict. Return {"ok": true} only if the message names the target, approval,
            and write scope and marks every checklist item pass or n/a with concrete
            evidence, with no required work left; or states a real blocker needing user
            input, approval, or external state and asks a direct question. Return
            {"ok": false, "reason": "the next concrete work"} for any missing, failed,
            unrun, unsafe, or unsupported item.
          timeout: 30
          continueOnBlock: true
---

# Dynamic verification

Target: IDA Professional 9.4 with ida-pro-mcp 3.4.0.

## Goal and stop contract

Before any IDA or MCP tool call, state a short working goal with target, execution approval,
IDB write scope, evidence, and Done checks: run the named target to test one exact claim;
finish when the observation is compared with the hypothesis, address rebasing is checked,
and the debuggee is stopped.

Update the working goal for a new runtime question. Keep working until the done checks
pass or an execution, environment, or tool blocker needs user action.

Final audit: mark every hook checklist item `pass`, `n/a`, or `blocked` and give evidence.
The hook blocks a stop when any required item is unproved.

The working goal does not grant execution approval.

## Safety gate

Do not call any `dbg_*` tool until all of these are true:

- the user has clearly approved running or attaching to this target;
- the executable, arguments, and attach or launch mode are known;
- untrusted code is in an isolated VM or sandbox with suitable network and host controls;
- an IDA GUI session has a debugger selected and the target configured;
- the MCP server has unsafe debugger tools enabled;
- the exact runtime question and stop point are known.

Approval to run the target does not also grant IDB writes or `dbg_write`. Use the write
scope in the working goal. If `dbg_start` fails because setup is missing, report the
setup problem; do not retry in a loop.

Debugger and Python tools are hidden extensions and `MCP_UNSAFE`; the general `batch`
tool rejects them. Use each debugger tool in state order. Use native list inputs to set
several breakpoints, conditions, or memory reads in one call.

## Evidence rule

Registers and memory at a breakpoint are direct evidence for that process, input, thread,
and time. They do not prove all runs. Read the static instruction too: it gives the access
width and operation that the live value is taking part in.

## 1. State a testable hypothesis

Use static work first. State one claim, for example:

- “this allocation request is `0x48` on the selected path”;
- “the access at `<instruction>` reads four bytes from base plus `0x10`”;
- “the indirect call at `<instruction>` reaches `<candidate>`”;
- “the first three Microsoft x64 argument positions hold these value classes.”

Pick the exact instruction where the claim can be observed. Read it with `disasm` before
launch. Note the static image base and the module whose code will run.

## 2. Run to the evidence point

A common launch flow is:

```text
dbg_start({})
dbg_add_bp({"addrs":["<static instruction>"]})
dbg_continue({})
dbg_status({})
dbg_regs_named({"register_names":"RAX, RCX, RDX, R8, R9"})
dbg_read({"regions":[{"addr":"<live pointer>","size":64}]})
dbg_stacktrace({})
dbg_exit({})
```

Set all needed breakpoints before `dbg_continue`. Use `dbg_run_to` for a checked one-shot
location: `dbg_run_to({"addr":"<static instruction>"})`. Use `dbg_step_into` or
`dbg_step_over` only until the stated evidence instruction has run or the stop condition
is met.

For a hot breakpoint, use a condition:

```text
dbg_set_bp_condition({"items":[
  {"addr":"<breakpoint>","condition":"RCX == 0x1000","language":"python"}
]})
```

The condition syntax depends on the selected debugger and expression language. Test it at
a safe point before relying on it to filter hostile or high-volume code.

Always call `dbg_exit` when the observation is complete or an error ends the run, unless
the user explicitly asked to leave the process live.

## 3. Read each fact with its limits

### Allocation request

Break at the call site, not only at a shared allocator entry. Read the size from the
correct ABI position, step over the call, and read the returned pointer.

The observed value is the allocation request for that call. It is exact `sizeof(T)` only
if one complete `T` is allocated with no wrapper header, trailer, array count, flexible
tail, or spare capacity.

### Field access

Break at the access. The instruction gives offset and width; the debugger gives the live
base, effective address, and value. One hit proves that access on that path.

To watch later writes, `dbg_add_bp` is for code breakpoints. If hardware watchpoints are
supported, an approved `py_eval` call can use IDAPython:

```python
import ida_dbg
import ida_idd
ida_dbg.add_bpt(live_address, size, ida_idd.BPT_WRITE)
```

The highest observed `offset + width` is a lower bound on touched extent. It is not the
full struct size unless separate allocation or stride evidence proves that size.

### Arguments

Break at both the call site and callee entry when possible. Map live values to the known
ABI positions and check their use. A plausible pointer in an argument register can be a
stale value, so one live sample does not prove a formal parameter.

### Indirect call or vtable slot

Break at the indirect transfer and read the computed target and object or table pointer.
Check that the target lies in the expected loaded module and maps to a valid static
function.

### Produced data

Break after the producer. Read the buffer and its known length. Do not read beyond the
validated region only to search for more text or keys.

## 4. Convert runtime addresses

ASLR changes module addresses. Before applying a name or comment, compute:

```text
static_ea = runtime_ea - runtime_module_base + IDB_image_base
```

`dbg_stacktrace` gives a module name, symbol, and frame address; it does not give the
module base. Get the base from a debugger event already recorded by the user, or use an
approved `py_eval` call with IDA 9.4's `ida_dbg.get_module_info(runtime_ea, modinfo)` and
read `modinfo.base`. Check whether IDA rebased the IDB before applying the formula, or the
offset will be added twice. `int_convert` can normalize one number's base, sign, and
width; it does not do the subtraction and addition in the rebase formula. Range-check the
final static address against the IDB segments.

## 5. Compare and record

State whether the observation confirms, rejects, or does not settle the hypothesis. For a
load-bearing claim, observe a second suitable instance or call site when safe and useful.

In approved IDB-write mode:

- size or layout evidence routes to **ida-struct-recovery**;
- ABI evidence routes to **ida-calling-convention**;
- a confirmed COM slot or SDK object routes to **ida-sdk-types** for its one-to-one type;
- an indirect target may support `rename` and `set_type`;
- produced data may support `set_comments`.

For a target that needs both facts, use `rename` for the name and `set_type` for the type,
then read both back. Recompile affected functions. In read-only IDB mode, make no IDB
change.

## Done

Finish only when:

- the target, input, environment, thread, and evidence instruction are stated;
- the static hypothesis and live observation are both recorded;
- the limits of the observation are stated;
- every runtime address used for a static claim was rebased and range-checked;
- approved IDB changes were recompiled and checked;
- `dbg_exit` stopped the process, or the user asked to keep it live;
- the report says confirm, reject, or not settled.
