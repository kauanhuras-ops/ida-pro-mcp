---
name: ida-sdk-types
description: Identify Windows SDK, DirectX, and COM APIs in an IDA database and give them their real SDK names, prototypes, structures, and flags one-to-one. Use when an import, ordinal, callback, or COM vtable call matches a known SDK API but IDA has not applied its full type.
hooks:
  Stop:
    - hooks:
        - type: prompt
          prompt: >-
            Decide whether Claude may stop the active ida-sdk-types task. Review
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

# Windows SDK and COM type recovery

## Goal and stop contract

Before any IDA or MCP tool call, set the working goal: identify the named SDK, DirectX, or
COM API surface in the requested read-only or IDB-write mode; finish when each named API
has an evidence source, a matching prototype, and its needed structs and flags declared and
checked against the bytes.

Update the working goal when the API set changes. Keep working until the done checks pass.
Do not declare, rename, or apply a type in read-only mode.

The frontmatter `Stop` hook checks the last response. Before a final response, include a
short completion audit with the target, write scope, checks run, results, and remaining
work. If required work remains, the hook blocks stopping and returns the next work.

## Evidence rule

An SDK identity is a hypothesis until an evidence source supports it. Strongest first: an
import symbol name, an ordinal-to-name map for the exact module, a CLSID or IID match, a
call-signature and behavior match. "It looks like DirectDraw" is not evidence. IDA often
names an import but does not apply the full SDK prototype, the referenced structs, or the
COM slot types. That gap is this skill's work. The SDK version matters: apply a prototype or
struct only when the module and its version fit, then confirm the struct against observed
offsets and widths.

## 1. Identify the API

Check each evidence source that applies:

- **Named imports.** `imports_query` for the module's used imports. A name such as
  `DirectDrawCreate`, `DirectSoundCreate8`, or `CreateWindowExW` is direct evidence.
- **Ordinal imports.** DirectX and older modules often import by ordinal (for example
  `ord_1` from `ddraw.dll`). Map ordinal to name only from a known table for that exact
  module and version; do not guess.
- **COM creation.** A `CoCreateInstance` or factory call takes a CLSID and an IID. The IID
  names the interface; each later call through the returned pointer is a virtual slot with a
  known prototype. This is the main path for DirectX, which is COM based.
- **GUID data.** A CLSID or IID is a 16-byte value in read-only or data memory. Match it to
  find the interface even without symbols:

```text
find_bytes({"patterns":["<16 GUID bytes as hex>"]})
xref_query({"queries":[{"addr":"<guid>","direction":"to","include_fn":true}]})
```

- **Callbacks.** Window procedures, dialog procs, and enum callbacks have fixed SDK
  prototypes; type them once their registration site is confirmed.

State the evidence source for every API you name. If only weak signs exist, keep the name a
hypothesis and add a `?` comment in approved write mode.

## 2. Get the types

Prefer a checked type library, then fall back to exact hand declarations.

1. **Load an IDA type library** when the API is covered. In approved write mode an approved
   `py_eval` call can add one:

```python
import ida_typeinf
ida_typeinf.add_til("mssdk64", ida_typeinf.ADDTIL_DEFAULT)
```

   Then `import_type` / `type_inspect` to confirm the struct exists.
2. **Declare the SDK types one-to-one** when the library does not cover them (common for
   DirectDraw, DirectSound, and Direct3D structs and interfaces). Copy the layout from the
   SDK header for the right version:

```text
declare_type({"decls":[
  "struct IDirectDrawSurface_vtbl;",
  "struct IDirectDrawSurface { struct IDirectDrawSurface_vtbl *lpVtbl; };",
  "struct IDirectDrawSurface_vtbl { HRESULT (__stdcall *QueryInterface)(struct IDirectDrawSurface *, const IID *, void **); ULONG (__stdcall *AddRef)(struct IDirectDrawSurface *); ULONG (__stdcall *Release)(struct IDirectDrawSurface *); /* then the interface-specific slots in header order */ };"
]})
```

3. **Declare the enums and flag sets** the API uses (`DDSD_*`, `DSBCAPS_*`, `D3DFVF_*`) with
   `enum_upsert`, so flag operands render by name.

Keep the SDK typedefs (`HRESULT`, `HWND`, `DWORD`, `LPDIRECTDRAWSURFACE`, and so on) so the
decompiler output reads like the SDK.

## 3. Apply in the right order: rename first, then type

In IDA, naming and typing are separate operations, and applying a type does not reliably
keep a symbol name. Always do the name first, then the type, as separate steps:

```text
rename({"batch":{"func":[{"addr":"<thunk or function>","name":"DirectDrawCreate"}]}})
set_type({"edits":[{"addr":"<thunk or function>","signature":"HRESULT __stdcall DirectDrawCreate(GUID *lpGUID, LPDIRECTDRAW *lplpDD, IUnknown *pUnkOuter)"}]})
```

For a COM object pointer, rename the variable, then apply the interface type:

```text
rename({"batch":{"local":[{"func_addr":"<owner>","old":"v5","new":"dd_surface"}]}})
set_type({"edits":[{"addr":"<owner>","variable":"dd_surface","ty":"struct IDirectDrawSurface *"}]})
force_recompile({"items":[{"addr":"<owner>"}]})
```

Do not put the new name in the type edit's `name` field and skip the rename; apply the type
after the rename and check that the name survived. Batch names together and types together,
but keep the name step before the type step.

## 4. Verify against the bytes

- The declared struct offsets and widths must match the observed accesses in `disasm`. A
  mismatch means the wrong SDK version or the wrong struct (for example `DDSURFACEDESC`
  versus `DDSURFACEDESC2`); fix the declaration, do not bend an observed offset.
- Each COM slot index must match the interface order in the header; confirm a slot by a call
  site before naming it (see `ida-cpp-rtti` for vtable handling).
- After `force_recompile`, the call should read like the SDK: named function, typed
  arguments, and `desc->dwFlags` instead of `*(a1 + 8)`.

## Dynamic check

Use **ida-dynamic-verify** only with explicit approval when a COM slot target, an ordinal
map, or a struct variant cannot be settled statically. Read the object and its vtable at
runtime, confirm the slot target is in the expected module, then rebase before recording.

## Done

Finish only when:

- each named API states its evidence source (import, ordinal map, GUID, or checked behavior);
- applied prototypes use the correct SDK types and convention;
- referenced SDK structs and flag sets are declared and their offsets match the bytes;
- COM interfaces have the right vtable order and only confirmed slots are named;
- every rename was done before its type application and the names survived;
- approved changes were recompiled and read back;
- unmapped ordinals, unknown GUIDs, and version doubts are stated.
