---
name: ida-cpp-rtti
description: Recover C++ classes from constructors, RTTI, and vtables over IDA Pro MCP. Use on C++ targets when vtable pointer writes, virtual calls, RTTI data, or mangled names can seed class size, field types, method names, and the base graph.
hooks:
  Stop:
    - hooks:
        - type: prompt
          prompt: >-
            Decide whether Claude may stop the active ida-cpp-rtti task. Review
            $ARGUMENTS, especially last_assistant_message. Checklist: class and RTTI or
            structural evidence; size bounds; slot evidence; object ABI; bases and VFTs;
            approved writes and read-back; open fields or slots. Return {"ok": true} only
            if the message names the target and write scope and marks every checklist item
            pass or n/a with concrete evidence, with no required work left; or states a
            real blocker needing user input, approval, or external state and asks a direct
            question. Return {"ok": false, "reason": "the next concrete work"} for any
            missing, failed, unrun, or unsupported item.
          timeout: 30
          continueOnBlock: true
---

# C++ class recovery from RTTI and constructors

Target: IDA Professional 9.4 with ida-pro-mcp 3.4.0.

## Goal and stop contract

Before any IDA or MCP tool call, state a short working goal with target, scope, evidence,
and Done checks: recover the named class layout and any present vtables, methods, and bases
for the named owners in the requested read-only or IDB-write mode; finish when every
claimed field, slot, and base has evidence.

Update the working goal when the class or owner set changes. Keep working until the done
checks pass. Do not declare or apply a type in read-only mode.

Final audit: mark every hook checklist item `pass`, `n/a`, or `blocked` and give evidence.
The hook blocks a stop when any required item is unproved.

## Evidence rule

RTTI data, mangled names, IDA auto-classes, and vtable symbols are strong hints, but they
are still hypotheses. Check each one against disassembly: the constructor writes, the slot
loads, and the object ABI. A constructor is the richest single seed, but its writes alone
do not prove that no later or read-only field exists. Use `ida-struct-recovery` discipline
for the layout and `ida-calling-convention` for the object ABI.

## 1. Use existing analysis, then check it

IDA often already parsed MSVC RTTI and made class types, vtable symbols, and demangled
names. If the exact type name is known, inspect it directly:

```text
type_inspect({"queries":[{"name":"Foo","include_members":true}]})
```

If the exact name is not known, use one discovery call: `type_query` for filtered,
paginated type data, or `search_structs` for a simple UDT substring search. Inspect the
chosen result afterward; that second call depends on the first result and must not be put
in `batch` with it.

Do not trust auto-RTTI blindly. Read table entries with one native-list `get_int` call,
resolve the code pointers with one native-list `lookup_funcs` call, and check constructor
writes with `disasm`. `disasm` is for functions, not vtable data. Extend and correct
existing types; do not rebuild what is already right.

## 2. Find vtables and class names

A vtable address point starts a run of virtual-function slots in read-only data that some
function writes to an object. Metadata or ABI offset entries may sit before the address
point and are not function slots. Confirm the slot run and the object write.

On MSVC, a complete-object locator pointer sits just before the vtable slot array
(`vtable[-1]`). It leads to a type descriptor whose name field holds the mangled class name
`.?AVClassName@@` (or `.?AU...` for a struct). Find the type descriptor names, then walk to
the vtable:

```text
find_regex({"pattern":"\\.\\?A[UV]","limit":100,"offset":0})
get_int({"queries":[
  {"addr":"<type-descriptor RVA field>","ty":"u32le"},
  {"addr":"<class-descriptor RVA field>","ty":"u32le"},
  {"addr":"<self RVA field>","ty":"u32le"}
]})
```

Follow `find_regex.cursor.next` when it is present. For vtable slots, read a bounded set of
pointer-sized values with `get_int`, then pass their values together to `lookup_funcs`.
Use the binary's pointer width and byte order; the `u32le` reads above are only for the
three MSVC x64 locator RVA fields.

On MSVC x64, first check the locator signature. The type-descriptor, class-descriptor, and
self fields in a signature-1 locator are 32-bit image-relative values. Read them as four-byte
RVAs and add the image base; do not read them as 64-bit absolute pointers. On x86, use the
matching absolute-pointer layout.

Demangle the name with IDA, or with an approved `py_eval` call:

```python
import ida_name
ida_name.demangle_name("??0CFoo@@QEAA@XZ", ida_name.MNG_LONG_FORM)
```

For Itanium or GCC, use the matching data: type-info objects, vtables with an offset-to-top
and a type-info pointer before the slot array, and `_Z` mangled names. If RTTI is absent,
skip to the no-RTTI notes below.

## 3. Find constructors and destructors

A function that writes a known vtable address to an object may be a constructor, destructor,
base-init helper, or object-reset routine. Treat it as a candidate and use the write as a
seed, not as final proof:

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
- **VFT pointer.** The vtable write gives a VFT-pointer field, normally at offset zero. In
  the IDA declaration, name it `__vftable`.
- **Bases.** A call to another constructor on `this` (or `this + offset`) near the start is
  a base subobject. Recover that base first and nest it.
- **Members.** Each `this + offset = value` write is a field candidate; type it from the
  value and its later use (pointer, integer width, embedded object from a member
  constructor). Keep unknown space as explicit padding.

```text
declare_type({"decls":[
  "struct __cppobj CFoo;",
  "struct CFoo_vtbl { void (*slot_0)(CFoo *__hidden this); int (*run)(CFoo *__hidden this, int); };",
  "struct __cppobj CFoo { CFoo_vtbl *__vftable; int state; char *name; };"
]})
```

For IDA 9.4 C++ object rendering, mark the object `__cppobj`, name the VFT-pointer field
`__vftable`, and use the `ClassName_vtbl` type pattern. Use `__hidden this` for the object
parameter. The example keeps slot zero neutral and gives `run` a role only as an example
of a checked slot.

## 5. Type the vtable and name checked methods

Each slot is a virtual method that takes the object as its first argument. Confirm the
object ABI first: x86 member calls commonly pass `this` in `ECX` (thiscall), and x64 passes
it in the first integer register. Verify with `ida-calling-convention`.

- Name a slot function `Class::method` only when its role has evidence (a demangled symbol,
  a clear string, or checked behavior). Do not name a slot from its index alone.
- Set each checked slot prototype with the object as the first parameter.
- Use `rename` for a new method name and `set_type` for its prototype. They are separate
  operations; read both results back.
- Apply the object type to `this` in proven methods, and set the vtable global type:

```text
type_apply_batch({"batch":{"edits":[
  {"kind":"local","addr":"<method1>","variable":"a1","ty":"struct CFoo *"},
  {"kind":"local","addr":"<method2>","variable":"this","ty":"struct CFoo *"}
]}})
make_data({"items":[{"addr":"<vtable>","type":"struct CFoo_vtbl vtable_object","name":"CFoo_vtbl_instance"}]})
force_recompile({"items":[{"addr":"<method1>"},{"addr":"<method2>"}]})
```

Read the methods again. A virtual call should now show a named slot. If it does not, the
slot type or object type disagrees with the bytes; fix the declaration, not the call.
The declaration, type application, and recompile steps are dependent; do not put them in
one general `batch`. Use native lists inside each step.

## 6. Rebuild the base graph

When RTTI has a class-hierarchy descriptor and a base-class array, use them to list bases
and their offsets. Declare base structs, nest them at the right offsets, and place each
base vptr. Multiple or virtual inheritance gives several vtables, base-offset fields, and
small adjustor thunks (a `this` fixup and a jump). Name a confirmed thunk as a thunk; do
not treat it as class logic.

For a secondary VFT at offset `XXXX`, IDA 9.4 uses the type name
`ClassName_XXXX_vtbl`, such as `Derived_0008_vtbl`. Keep the target compiler setting in IDA
matched to the binary because MSVC and Itanium layouts differ.

## No-RTTI, COM, and Itanium notes

- **No RTTI (`/GR-` or stripped).** No class names. Detect a class by structure: a
  read-only run of code pointers that a function writes to an object at offset zero. Use a
  neutral name from a checked constructor address, or from the vtable address when the
  writer's role is not known (for example `Class_401230`). A non-virtual class has no
  vtable; recover it through allocation and access evidence with `ida-struct-recovery`.
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

- each recovered class names its evidence: RTTI or structural detection, plus constructor,
  destructor, helper, or other object-use evidence when present;
- size claims are marked exact, upper bound, or lower bound, not assumed from the
  constructor alone;
- each named method slot has behavior or symbol evidence, and unknown slots keep neutral
  slot names;
- the object ABI (`this` register and convention) is stated; in IDB-write mode it is applied
  to approved methods;
- base classes, adjustor thunks, and any multiple-vtable layout are described;
- approved declarations and applications were recompiled and read back;
- open slots, missing RTTI, and unresolved fields are stated.
