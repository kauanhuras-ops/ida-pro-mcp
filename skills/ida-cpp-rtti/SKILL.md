---
name: ida-cpp-rtti
description: Recover C++ classes on MSVC/Windows (and Itanium/GCC) by seeding from constructors, RTTI, and vftables over IDA Pro MCP — the single richest source of class size, field types, method names, and the inheritance graph. Use on C++ targets: pseudocode with vftable writes at offset 0, virtual calls like (*(this->vtbl->m3))(this), mangled names (??0Class@@...), or an object threaded through many methods. Turns raw vtables into named Class_vtbl structs and unnamed sub_* into Class::method. Extends ida-struct-recovery for the polymorphic case; pairs with ida-cold-start (constructor seeding) and ida-calling-convention (this-call).
---

# C++ / RTTI recovery — constructors are the richest seed

> ⚠️ **GROUND TRUTH — TRUST ONLY THE DISASSEMBLY, AND YOUR OWN EYES.** Never trust the decompiler
> output or existing comments. **Comments lie** — stale, wrong, or deliberately misleading. **The
> decompiler guesses, errs, and silently breaks.** The disassembly is the bytes the CPU actually
> executes; it never lies. Every name, type, prototype, struct field, and conclusion must trace back
> to instructions you read yourself in `disasm` / `insn_query`. Whenever pseudocode or a comment
> disagrees with the disassembly, the disassembly wins — every time.

A constructor is the highest-value function in a C++ binary: in one place it gives you the object's
**size** (`operator new(sizeof)`), its **vftable** (written to offset 0), its **field types** (each
`this->field = …` init), its **base classes** (base-ctor calls), and — via the RTTI next to the
vftable — often the **real class name**. Seed class recovery from constructors, not from scattered
member accesses.

## Set the goal — `/goal`

On entry, pin the objective with the **`/goal`** command:
`/goal recover class <Name>: struct + vftable from ctor/RTTI, name every method, apply this across members`.

## Step 0 — Use what IDA already recovered (then verify it)

IDA auto-parses MSVC RTTI and often already created class structs, `??_7Class@@6B@` vftable symbols,
and demangled names. Check before doing manual work — but verify against the bytes, don't trust blindly:
```
search_structs(pattern="*")                       # existing class/vftable structs
type_query({ queries:[{ filter:"*", include_decl:true }] })   # what types exist
find_regex(pattern="\\.\\?A[UV]")                 # RTTI type-descriptor names ".?AVClass@@" / ".?AU..."
```
Extend and correct what's there rather than re-deriving from scratch.

## Step 1 — Find vftables and their class names via RTTI (MSVC layout)

MSVC lays out, in `.rdata`: `_RTTICompleteObjectLocator *` immediately **before** the vftable's
function-pointer array (i.e. `vftable[-1]` = the COL). The COL → `_TypeDescriptor` whose name field is
the mangled class name `.?AVClassName@@`.
```
find_regex(pattern="\\.\\?AV")                    # locate type descriptors -> class names
get_bytes / read_struct                           # read the COL / vftable pointer array in .rdata
```
For each vftable: demangle the class name and read the slot array (each entry is a virtual method).
Demangle with IDA (auto), or `py_eval`:
```python
import ida_name
ida_name.demangle_name("??0CFoo@@QEAA@XZ", ida_name.MNG_LONG_FORM)   # -> CFoo::CFoo(void)
```

## Step 2 — Find constructors/destructors from the vftable

Any function that **writes a known vftable address into `[this + 0]`** is a ctor (or the dtor, which
re-installs it). Link them:
```
xref_query({ addr:"??_7CFoo@@6B@", direction:"to", include_fn:true })   # who stores this vftable -> ctors/dtors
```
The object being written through is the `this` pointer of that class. Multiple vftable writes at
different offsets in one function ⇒ multiple inheritance (a vftable per base subobject).

## Step 3 — Recover the class struct from the constructor

Read the ctor's `disasm`/`decompile` and build the layout:
- **Size** from `operator new(sizeof)` (or `malloc`) at the allocation site that feeds this ctor.
- **vftable** pointer at offset 0 → field `Class_vtbl *vftable;`.
- **Base classes**: a call to another ctor on `this` (or `this+off`) at the *start* is a base-class
  subobject — recover that base first and nest it (`struct Derived { Base base; … };`).
- **Members**: each `this->field = value` initializes a field — type it from the value (pointer,
  int width from access, another object from a member-ctor call). Embedded object ⇒ nested struct.
- Leave unobserved gaps as `char gapN[k]` (see `ida-struct-recovery` discipline).
```
declare_type(decls=[
  "struct CFoo_vtbl { void (__fastcall *dtor)(CFoo*); int (__fastcall *run)(CFoo*, int); };",
  "struct CFoo { CFoo_vtbl *vftable; int state; char *name; };"
])
```

## Step 4 — Type the vftable and name the methods

Each vftable slot is a virtual method taking `this` as the first parameter. Convention: **x86
`__thiscall`** (`this` in `ecx`), **x64** standard fastcall (`this` in `rcx`) — confirm via
`ida-calling-convention`.
- Name each slot function `Class::method` (`rename`), demangling any mangled symbol for the real name.
- Set each method's prototype with `this` first (`set_type` / `type_apply_batch`).
- Apply the `Class *` type to `this` across every method (`type_apply_batch`), and `make_data` the
  vftable global as `Class_vtbl`.
Now `(*(this->vftable->run))(this, x)` renders as a named virtual call, everywhere.

## Step 5 — Rebuild the inheritance graph (RTTI hierarchy)

`_RTTIClassHierarchyDescriptor` + `_RTTIBaseClassArray` (reachable from the COL) enumerate all bases
and their offsets. Use them to declare base structs, nest them at the right offsets, and place each
base's vftable pointer. Multiple/virtual inheritance ⇒ several vftables + vbase offsets + adjustor
thunks (tiny functions that fix `this` by a constant then jump) — name the thunks and move on.

## Non-MSVC and no-RTTI fallbacks

- **Itanium/GCC** (`_ZTV` vtables, `_ZTI` typeinfo, `_Z`-mangled names): same idea, different symbols;
  demangle via IDA. Vtable layout has an offset-to-top + typeinfo pointer *before* the slot array.
- **RTTI stripped (`/GR-`) or optimized:** no names. Detect classes structurally — a `.rdata` array of
  code pointers that some function writes to `[obj+0]` is a vftable; name the class generically
  (`Class_401230`) from its ctor address and proceed. Non-virtual classes have no vftable at all →
  recover them via allocation-driven discovery (`ida-cold-start` / `ida-struct-recovery`).
- **COM interfaces:** vtable-only, first three slots are `QueryInterface`/`AddRef`/`Release`
  (IUnknown); type them from the standard signatures.

## Verify & persist

- Demangled/RTTI name matches the mangled symbol and the class's behaviour (spot-check a method).
- `type_inspect` the class: size matches the `operator new` constant; base offsets line up.
- Every member method renders `this->field` by name and virtual calls resolve to `Class::method`.
- Commit continuously — each recovered vftable, named method, and typed field is written the moment
  it's confirmed, not saved for a final dump.

## Traps

- **Trusting IDA's auto-RTTI blindly** — usually right, but verify the vftable slot count and the
  ctor's actual writes against `disasm`; stripped/partial RTTI produces gaps.
- **Wrong `this` convention** — x86 `__thiscall` vs x64 fastcall; getting it wrong scrambles every
  method's args (→ `ida-calling-convention`).
- **Confusing ctor with dtor** — both write the vftable; the dtor also frees/tears down. Check for
  `operator delete` / member cleanup to tell them apart.
- **Adjustor thunks look like real methods** — a 2-instruction `sub ecx, N; jmp` is a `this`-adjust
  for a base, not logic; name it as a thunk.
