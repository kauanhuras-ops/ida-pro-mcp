---
name: ida-cpp-rtti
description: Recover C++ classes from constructors, RTTI, and vtables over IDA Pro MCP. Use on C++ targets when vtable pointer writes, virtual calls, RTTI data, or mangled names can seed class size, field types, method names, and the base graph.
hooks:
  Stop:
    - hooks:
        - type: prompt
          prompt: >-
            Decide whether Claude may stop the active ida-cpp-rtti task. Review
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

# C++ class recovery from RTTI and constructors

## Goal and stop contract

Before any IDA or MCP tool call, set the working goal: recover the named class (its layout,
vtable, methods, and bases) for the named owners in the requested read-only or IDB-write
mode; finish when every claimed field, slot, and base has evidence.

Update the working goal when the class or owner set changes. Keep working until the done
checks pass. Do not declare or apply a type in read-only mode.

The frontmatter `Stop` hook checks the last response. Before a final response, include a
short completion audit with the target, write scope, checks run, results, and remaining
work. If required work remains, the hook blocks stopping and returns the next work.

## Evidence rule

RTTI data, mangled names, IDA auto-classes, and vtable symbols are strong hints, but they
are still hypotheses. Check each one against disassembly: the constructor writes, the slot
loads, and the object ABI. A constructor is the richest single seed, but its writes alone
do not prove that no later or read-only field exists. Use `ida-struct-recovery` discipline
for the layout and `ida-calling-convention` for the object ABI.

## 1. Use existing analysis, then check it

IDA often already parsed MSVC RTTI and made class types, vtable symbols, and demangled
names. Read what exists before making new types:

```text
search_structs({"filter":"Foo"})
type_query({"queries":[{"filter":"*","include_decl":true}]})
type_inspect({"queries":[{"name":"Foo","include_members":true}]})
```

Do not trust auto-RTTI blindly. Confirm the vtable slot count and the constructor writes in
`disasm` before you rely on them. Extend and correct existing types; do not rebuild what is
already right.

## 2. Find vtables and class names

A vtable is a run of code pointers in read-only data that some function writes to an object
at offset zero. Confirm both parts: the pointer run and the write.

On MSVC, a complete-object locator pointer sits just before the vtable slot array
(`vtable[-1]`). It leads to a type descriptor whose name field holds the mangled class name
`.?AVClassName@@` (or `.?AU...` for a struct). Find the type descriptor names, then walk to
the vtable:

```text
find_regex({"pattern":"\\.\\?A[UV]"})
get_bytes({"regions":[{"addr":"<locator or slot array>","size":64}]})
```

Demangle the name with IDA, or with an approved `py_eval` call:

```python
import ida_name
ida_name.demangle_name("??0CFoo@@QEAA@XZ", ida_name.MNG_LONG_FORM)
```

For Itanium or GCC, use the matching data: type-info objects, vtables with an offset-to-top
and a type-info pointer before the slot array, and `_Z` mangled names. If RTTI is absent,
skip to the no-RTTI notes below.

## 3. Find constructors and destructors

A function that writes a known vtable address to the object at offset zero is a constructor
or the destructor (the destructor re-installs the table during teardown):

```text
xref_query({"queries":[{"addr":"<vtable symbol or address>","direction":"to","include_fn":true}]})
```

The object written through is the `this` value for that class. Two vtable writes at
different offsets in one function suggest multiple base subobjects. Tell a constructor from
a destructor by its other behavior: a constructor runs base and member setup and often
follows an allocation; a destructor runs cleanup and often calls `operator delete`.

## 4. Recover the class layout from the constructor

Read the constructor with `disasm` and `decompile` and build a layout with evidence, using
the `ida-struct-recovery` rules:

- **Size bound.** If an allocation feeds this object, its request is a size hint, not proof.
  It equals `sizeof(T)` only when one whole object is allocated with no wrapper header,
  trailer, array, or spare capacity. Constructor writes do not prove the full size.
- **vptr.** The vtable write gives a `vptr` field, normally at offset zero.
- **Bases.** A call to another constructor on `this` (or `this + offset`) near the start is
  a base subobject. Recover that base first and nest it.
- **Members.** Each `this + offset = value` write is a field candidate; type it from the
  value and its later use (pointer, integer width, embedded object from a member
  constructor). Keep unknown space as explicit padding.

```text
declare_type({"decls":[
  "struct CFoo_vtbl;",
  "struct CFoo_vtbl { void (*dtor)(struct CFoo *); int (*run)(struct CFoo *, int); };",
  "struct CFoo { struct CFoo_vtbl *vptr; int state; char *name; };"
]})
```

## 5. Type the vtable and name checked methods

Each slot is a virtual method that takes the object as its first argument. Confirm the
object ABI first: x86 member calls commonly pass `this` in `ECX` (thiscall), and x64 passes
it in the first integer register. Verify with `ida-calling-convention`.

- Name a slot function `Class::method` only when its role has evidence (a demangled symbol,
  a clear string, or checked behavior). Do not name a slot from its index alone.
- Set each checked slot prototype with the object as the first parameter.
- Run the slot `rename` step before the slot `set_type` step; a type application does not
  reliably keep a name in IDA. Check that the name survived.
- Apply the object type to `this` in proven methods, and set the vtable global type:

```text
type_apply_batch({"batch":{"edits":[
  {"addr":"<method1>","variable":"a1","ty":"struct CFoo *"},
  {"addr":"<method2>","variable":"this","ty":"struct CFoo *"}
]}})
make_data({"items":[{"addr":"<vtable>","type":"struct CFoo_vtbl","name":"CFoo_vtbl_instance"}]})
force_recompile({"items":[{"addr":"<method1>"},{"addr":"<method2>"}]})
```

Read the methods again. A virtual call should now show a named slot. If it does not, the
slot type or object type disagrees with the bytes; fix the declaration, not the call.

## 6. Rebuild the base graph

When RTTI has a class-hierarchy descriptor and a base-class array, use them to list bases
and their offsets. Declare base structs, nest them at the right offsets, and place each
base vptr. Multiple or virtual inheritance gives several vtables, base-offset fields, and
small adjustor thunks (a `this` fixup and a jump). Name a confirmed thunk as a thunk; do
not treat it as class logic.

## No-RTTI, COM, and Itanium notes

- **No RTTI (`/GR-` or stripped).** No class names. Detect a class by structure: a
  read-only run of code pointers that a function writes to an object at offset zero. Name
  the class from its constructor address (for example `Class_401230`) and go on. A
  non-virtual class has no vtable; recover it through allocation and access evidence with
  `ida-struct-recovery`.
- **COM interfaces.** These are vtable-only. The first three slots are `QueryInterface`,
  `AddRef`, and `Release` (IUnknown). Type them from the standard signatures and confirm by
  use. For a known interface (from a CLSID/IID or a DirectX API), take the full slot
  prototypes and structs one-to-one from **ida-sdk-types** instead of deriving each slot.
- **Itanium or GCC.** Same idea, different data and mangling; demangle `_Z` names with IDA.

## Dynamic check

Use **ida-dynamic-verify** only with explicit approval when static evidence cannot settle a
load-bearing size, slot target, or base offset. Read the object at runtime, or the computed
target of a virtual call, then rebase the address before recording it.

## Done

Finish only when:

- each recovered class names its evidence: vtable write, RTTI or structural detection, and
  constructor behavior;
- size claims are marked exact, upper bound, or lower bound, not assumed from the
  constructor alone;
- each named method slot has behavior or symbol evidence, and unknown slots are left
  unnamed;
- the object ABI (`this` register and convention) is stated and applied;
- base classes, adjustor thunks, and any multiple-vtable layout are described;
- approved declarations and applications were recompiled and read back;
- open slots, missing RTTI, and unresolved fields are stated.
