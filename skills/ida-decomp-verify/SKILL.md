---
name: ida-decomp-verify
description: Check Hex-Rays pseudocode against IDA disassembly and fix the source of supported mismatches when IDB changes are allowed.
hooks:
  Stop:
    - hooks:
        - type: prompt
          prompt: >-
            Decide whether Claude may stop the active ida-decomp-verify task. Review
            $ARGUMENTS, especially last_assistant_message. Checklist: calls, transfers, and
            memory effects; ABI rendering; widths and signs; function bounds; approved
            fixes and read-back; remaining decompiler loss. Return {"ok": true} only if
            the message names the target and write scope and marks every checklist item
            pass or n/a with concrete evidence, with no required work left; or states a
            real blocker needing user input, approval, or external state and asks a direct
            question. Return {"ok": false, "reason": "the next concrete work"} for any
            missing, failed, unrun, or unsupported item.
          timeout: 30
          continueOnBlock: true
---

# Decompiler verification

Target: IDA Professional 9.4 with ida-pro-mcp 3.4.0.

## Goal and stop contract

Before any IDA or MCP tool call, state a short working goal with target, scope, evidence,
and Done checks: verify pseudocode for the named function in the requested read-only or
IDB-write mode; finish when control transfers, calls, memory effects, widths, signs, and
prototype use agree with checked disassembly.

Update the working goal for each new function. Keep working until the done checks pass.
Do not fix the IDB in read-only mode; report the smallest supported fix instead.

Final audit: mark every hook checklist item `pass`, `n/a`, or `blocked` and give evidence.
The hook blocks a stop when any required item is unproved.

## Evidence rule

Pseudocode, current names, types, comments, and even current function bounds are
hypotheses. Use disassembly and raw bytes as the main static evidence. If decoding or
code/data boundaries are wrong, repair or account for that before blaming the decompiler.

## 1. Make a semantic comparison

```text
batch({"calls":[
  {"id":"pseudo","tool":"decompile","arguments":{"addr":"<function>"}},
  {"id":"asm","tool":"disasm","arguments":{"addr":"<function>","offset":0,"max_instructions":5000,"include_total":true}},
  {"id":"cfg","tool":"basic_blocks","arguments":{"addrs":["<function>"]}}
]})
```

These three bounded reads are independent, so the general `batch` saves MCP round trips.
Results stay in input order and keep their IDs. `disasm.asm.lines` is one
newline-delimited string; follow its cursor and page with `offset` when it is not done.

Compare effects, not one pseudocode line per instruction. Prologues, spills, register
copies, address calculations, and some optimized work may not have separate C statements.

Flag a mismatch when it changes meaning:

- a call, branch, indirect transfer, or side effect is missing;
- pseudocode shows an argument, value, or path with no instruction basis;
- an access width or signed operation changes the result;
- a function boundary or jump target is wrong;
- a no-return or calling-convention guess removes or changes reachable code.

Use `insn_query` to find candidates, then read the full local disassembly before deciding:

```text
insn_query({"queries":[
  {"func":"<function>","mnem":"call","include_disasm":true},
  {"func":"<function>","mnem":"movsx","include_disasm":true}
]})
```

This uses the tool's native list input. Do not use general `batch` for repeated calls to
the same tool.

## 2. Find the source

| Symptom | Common source | Check |
|---|---|---|
| Missing or extra arguments | wrong callee prototype or hidden ABI argument | callee use and several call sites |
| Raw `__int64`, `_QWORD`, or casts | missing variable, stack, or struct type | access widths and value use |
| Wrong signed operation | wrong local, parameter, or return type | extending op, compare, division, and caller use |
| Missing block | wrong no-return fact, bounds, or control-flow recovery | raw bytes, targets, and callee behavior |
| Stack noise | wrong stack item size or overlapping object | frame offsets and instruction widths |
| Bad switch | wrong table type, bounds, or indirect targets | table bytes and CFG |
| Value appears uninitialized | bad call-clobber or prototype model | register life across the call |

These are starting points, not automatic fixes. For example, `movsx` proves a signed
extension at one use; it does not by itself prove the best source-language type.

## 3. Fix or report one mismatch at a time

For each confirmed mismatch:

1. State the disassembly fact and the pseudocode result that conflicts with it.
2. Find the smallest source fact that explains it. A common source is a missing or wrong
   Windows SDK / COM type on a call: the real prototype or struct fixes the render (use
   **ida-sdk-types**).
3. In IDB-write mode, apply only that fix:
   - `set_type` for a prototype or variable; each preferred edit has `kind` and `ty`, plus
     the locator required by that kind;
   - **ida-struct-recovery** for a layout;
   - `declare_stack` for a stack object;
   - `set_op_type` for a checked operand;
   - `define_func`, `define_code`, or `undefine` for checked boundary or code/data errors.
   If the fix also needs a new name, use an explicit `rename`; the type edit does not create
   that name. Read both facts back.
4. Call `force_recompile` for the function and affected callers or callees.
5. Compare again. The mismatch must be gone without a new semantic mismatch.

Boundary tools can replace IDB analysis items. Use them only when changes are approved and
raw bytes and targets support the new boundary.

If the source is another function's prototype or type, fix that in-scope source rather
than adding a local name that hides the problem. In read-only mode, report the source and
the proposed minimal fix.

## 4. Record a true decompiler limit

When checked disassembly has a stable meaning but Hex-Rays still cannot express it:

- state the correct semantic reading;
- state why types, bounds, and prototypes do not remove the mismatch;
- in approved write mode, add a short comment at the relevant address;
- do not use a false C type or name to make pseudocode look cleaner.

Do not call a case a Hex-Rays bug until bad input facts have been checked.

## Done

Finish only when:

- every behavior-changing call, transfer, branch, and memory effect is represented or
  explained;
- argument and return rendering agrees with checked ABI evidence;
- important widths and signed operations agree;
- function bounds and jump targets are sound for the checked scope;
- every approved fix was recompiled and checked again;
- remaining presentation-only loss or decompiler limits are stated.

A clean-looking decompile alone is not a done check.
