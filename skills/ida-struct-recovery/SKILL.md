---
name: ida-struct-recovery
description: Recover evidence-based structs, classes, unions, and vtables from IDA disassembly. Use when raw base-plus-offset accesses hide a shared layout.
hooks:
  Stop:
    - hooks:
        - type: prompt
          prompt: >-
            Decide whether Claude may stop the active ida-struct-recovery task. Review
            $ARGUMENTS, especially last_assistant_message. Checklist: member offset, width,
            use, and type evidence; gaps and overlays; size bounds; owner set and applied
            types; approved writes and read-back; conflicts and open layout questions.
            Return {"ok": true} only if the message names the target and write scope and
            marks every checklist item pass or n/a with concrete evidence, with no required
            work left; or states a real blocker needing user input, approval, or external
            state and asks a direct question. Return {"ok": false, "reason": "the next
            concrete work"} for any missing, failed, unrun, or unsupported item.
          timeout: 30
          continueOnBlock: true
---

# Struct recovery

Target: IDA Professional 9.4 with ida-pro-mcp 3.4.0.

## Goal and stop contract

Before any IDA or MCP tool call, state a short working goal with target, scope, evidence,
and Done checks: recover the named type for the named owners in the requested read-only or
IDB-write mode; finish when every claimed field offset, width, type, and size bound has
evidence.

Update the working goal when the owner set or type target changes. Keep working until the
done checks pass. Do not declare or apply a type in read-only mode.

Final audit: mark every hook checklist item `pass`, `n/a`, or `blocked` and give evidence.
The hook blocks a stop when any required item is unproved.

## Evidence rule

Decompiler expressions and current types are hypotheses. Use decoded memory operands,
access widths, calls, and data flow as static evidence. First check that the same base
value reaches each access. A runtime observation applies to the observed object and path
only.

## 1. Collect accesses

Find the base pointer used at constant offsets. For each access, record:

| Item | Evidence |
|---|---|
| owner function | function and basic block |
| base value | parameter, local, global, or loaded field |
| offset | encoded displacement |
| width | byte, word, dword, qword, vector, or other width |
| action | read, write, address-take, compare, or call |
| use | integer, pointer, array index, API argument, or callback |

Use `disasm` for the final width and operand check. `insn_query` can find candidates:

```text
insn_query({"queries":[{"func":"<owner>","mnem":"mov","include_disasm":true}]})
```

Use one native query list when several instruction patterns are needed. Then inspect only
the matching local ranges. `disasm.asm.lines` is one newline-delimited string; page it
with `offset` and `max_instructions`.

Do not assume every observed offset starts an independent field. An access may point into
an array, embedded object, union member, bitfield container, or unaligned data.

## 2. Form a layout model

For each candidate member:

- A dereference of the loaded value supports a pointer, but not its full pointed-to type.
- A known API parameter can support a stronger type.
- `movsx` or a signed comparison supports signed use; `movzx` or an unsigned comparison
  supports unsigned use at that site.
- Different types at the same offset may mean a union, reused storage, or a wrong base
  model.
- A call through a value loaded from the object supports a callback field. A virtual call
  normally has a separate load of a vtable pointer and then a slot load.

Keep unknown space as explicit padding only when later offsets need stable placement. Do
not give padding a semantic name.

Check existing types before making a new one. If the exact name is known, use
`type_inspect` directly. Use `type_query` or `search_structs` first only when discovery is
needed; a later inspect call depends on that result. Use `read_struct` only for an address
that already has a suitable applied type:

```text
type_inspect({"queries":[{"name":"Config","include_members":true}]})
read_struct({"queries":[{"addr":"<typed instance>"}]})
```

`read_struct` shows data through a type. It does not prove that the current type is right.

## 3. Track size evidence

Keep size facts separate:

- `max(offset + width)` is a lower bound on accessed extent.
- An array stride can support an element size when indexing proves the stride.
- An allocation request is the block request for that call. It equals `sizeof(T)` only
  when one complete `T` is allocated with no header, trailer, flexible data, or spare
  capacity.
- Constructor writes do not prove that no later or read-only fields exist.

State whether each size is exact, an upper bound, or a lower bound.

## 4. Declare and apply

If the base value is a known SDK, DirectX, or COM structure (from an API argument, a GUID,
or a COM interface), do not reinvent it. Declare the SDK layout one-to-one and confirm it
against the observed offsets — use **ida-sdk-types**. Reinvent a layout only for a type with
no known source.

In IDB-write mode, a partial declaration is useful when each named member has evidence:

```text
declare_type({"decls":[
  "struct Config; struct Config { int magic; char gap_4[4]; const char *path; int count; void (*on_close)(struct Config *); };"
]})
```

Check compiler alignment. If an offset does not match the evidence, use explicit padding
or the right packing rule; do not change an observed offset to fit the declaration.

Apply the type only to proven owners:

```text
set_type({"edits":[{"kind":"local","addr":"<owner>","variable":"a1","ty":"struct Config *"}]})
type_apply_batch({"batch":{"edits":[
  {"kind":"local","addr":"<owner1>","variable":"a1","ty":"struct Config *"},
  {"kind":"local","addr":"<owner2>","variable":"ctx","ty":"struct Config *"}
]}})
set_op_type({"items":[{"addr":"<instruction>","op_n":1,"kind":"stroff","struct":"Config","delta":0}]})
force_recompile({"items":[{"addr":"<owner1>"},{"addr":"<owner2>"}]})
```

Use `make_data` only when the task needs a data item to be created or replaced. For an
existing global, prefer `set_type` when it is enough.

When an owner variable or global needs a new name and a type, use the explicit name and type
operations and read both results back.

Read the owners again. A better decompile is a check on application, not proof of layout.
If new evidence conflicts with a field, correct the shared type and recheck every
affected owner.
Declaration, application, and recompile are dependent stages. Do not put them in one
general `batch`; use native lists within each stage.

## 5. C++ objects and vtables

A pointer at offset zero that leads to code pointers is a vptr candidate, not proof by
itself. Check:

1. constructor or setup writes of the table address;
2. indirect calls through stable table slots;
3. table xrefs, RTTI, or related tables when present;
4. the ABI form of the object parameter at each method;
5. slot prototypes at more than one call site when possible.

Declare the table as typed function-pointer fields only for checked slots. Do not name an
unknown slot from its index alone.

For a real C++ target with RTTI, mangled names, or many virtual calls, use **ida-cpp-rtti**.
It seeds a whole class from its constructor and RTTI (size hint, vptr, fields, methods, and
base graph) with the same evidence rules. The steps here are enough for a single vtable or
an object with no RTTI.

## Dynamic check

Use **ida-dynamic-verify** only with explicit approval when static evidence cannot settle
a load-bearing size, variant, or indirect target. A watchpoint hit gives a real access for
that run. The highest offset seen remains a lower bound unless allocation or stride
evidence proves the full extent.

## Done

Finish only when:

- each claimed member has offset, width, action, and type evidence;
- gaps, unions, arrays, embedded objects, and padding are not hidden by certain names;
- size claims are marked exact, upper bound, or lower bound;
- the owner set and all applied pointer types are listed;
- approved declarations and applications were read back after recompile;
- every known conflict was fixed and open layout questions are stated.
