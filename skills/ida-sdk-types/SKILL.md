---
name: ida-sdk-types
description: Identify Windows SDK, DirectX, and COM APIs in an IDA database and give them their real SDK names, prototypes, structures, and flags one-to-one. Use when an import, ordinal, callback, or COM vtable call matches a known SDK API but IDA has not applied its full type.
hooks:
  Stop:
    - hooks:
        - type: prompt
          prompt: >-
            Decide whether Claude may stop the active ida-sdk-types task. Review
            $ARGUMENTS, especially last_assistant_message. Checklist: API identity and
            evidence; exact target and SDK source; prototypes; structs and bitmask flags;
            COM slot order; approved writes and read-back; open version or mapping gaps.
            Return {"ok": true} only if the message names the target and write scope and
            marks every checklist item pass or n/a with concrete evidence, with no required
            work left; or states a real blocker needing user input, approval, or external
            state and asks a direct question. Return {"ok": false, "reason": "the next
            concrete work"} for any missing, failed, unrun, or unsupported item.
          timeout: 30
          continueOnBlock: true
---

# Windows SDK and COM type recovery

Target: IDA Professional 9.4 with ida-pro-mcp 3.3.0.

## Goal and stop contract

Before any IDA or MCP tool call, state a short working goal with target, scope, evidence,
and Done checks: identify the named SDK, DirectX, or COM API surface in the requested
read-only or IDB-write mode; finish when each named API has an evidence source and matching
prototype, and its needed structs and flags are checked against the bytes. In IDB-write
mode, also declare and apply the approved types.

Update the working goal when the API set changes. Keep working until the done checks pass.
Do not declare, rename, or apply a type in read-only mode.

Final audit: mark every hook checklist item `pass`, `n/a`, or `blocked` and give evidence.
The hook blocks a stop when any required item is unproved.

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
  known prototype. This is a common path for COM-based DirectX APIs.
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

1. **Load an IDA type library** when the API is covered. Select the file by target bitness
   and SDK line. IDA 9.4 uses versioned names such as `mssdk64_win10`, not `mssdk64`.
   In approved write mode, an approved `py_eval` call can load and import a named type:

```python
import ida_typeinf
import ida_netnode
import idc

rc = ida_typeinf.add_til("mssdk64_win10", ida_typeinf.ADDTIL_DEFAULT)
if rc != ida_typeinf.ADDTIL_OK:
    raise RuntimeError(f"TIL load failed or is compiler-incompatible: {rc}")

type_id = idc.import_type(-1, "_IMAGE_DOS_HEADER")
if type_id == ida_netnode.BADNODE:
    raise RuntimeError("type import failed")
```

   Replace the TIL and type names with the checked target values. There is no MCP
   `import_type` tool; the code above uses IDA 9.4's `idc.import_type`. Then use
   `type_inspect` to confirm the imported declaration, size, and members.
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
   `enum_upsert`. Set `bitfield` to `true` for flags, so combined values render by name:

```text
enum_upsert({"queries":[{"name":"DDSD_FLAGS","bitfield":true,"members":[{"name":"DDSD_CAPS","value":1},{"name":"DDSD_HEIGHT","value":2},{"name":"DDSD_WIDTH","value":4}]}]})
```

Keep the used SDK typedefs, such as `HRESULT`, `HWND`, `DWORD`, and
`LPDIRECTDRAWSURFACE`, so the decompiler output reads like the SDK.

## 3. Name and type with explicit operations

`rename` gives an entity a new name; `set_type` applies a type. Keep those operations
explicit and read both results back. This example names the function and then types it:

```text
rename({"batch":{"func":[{"addr":"<thunk or function>","name":"DirectDrawCreate"}]}})
set_type({"edits":[{"addr":"<thunk or function>","signature":"HRESULT __stdcall DirectDrawCreate(GUID *lpGUID, LPDIRECTDRAW *lplpDD, IUnknown *pUnkOuter)"}]})
```

For a COM object pointer, this example renames the variable first, so the later type edit
uses the new local name as its locator:

```text
rename({"batch":{"local":[{"func_addr":"<owner>","old":"v5","new":"dd_surface"}]}})
set_type({"edits":[{"addr":"<owner>","variable":"dd_surface","ty":"struct IDirectDrawSurface *"}]})
force_recompile({"items":[{"addr":"<owner>"}]})
```

Do not use a type edit's `name` field as a new name. It is an existing global or stack-member
locator. Batch related operations when useful, then read back the final name and type.

## 4. Verify against the bytes

- The declared struct offsets and widths must match the observed accesses in `disasm`. A
  mismatch means the wrong SDK version or the wrong struct (for example `DDSURFACEDESC`
  versus `DDSURFACEDESC2`); fix the declaration, do not bend an observed offset.
- Each COM slot index must match the interface order in the header; confirm a slot by a call
  site before naming it. This skill owns known interface identity, header order, and slot
  prototypes. Use `ida-cpp-rtti` only for unknown native C++ class or vtable discovery.
- After `force_recompile`, the call should read like the SDK: named function, typed
  arguments, and `desc->dwFlags` instead of `*(a1 + 8)`.

## Dynamic check

Use **ida-dynamic-verify** only with explicit approval when a COM slot target, an ordinal
map, or a struct variant cannot be settled statically. Read the object and its vtable at
runtime, confirm the slot target is in the expected module, then rebase before recording.

## Done

Finish only when:

- each named API states its evidence source (import, ordinal map, GUID, or checked behavior);
- each prototype uses the correct SDK types and convention;
- in read-only mode, referenced structs and bitmask flags have exact proposed declarations;
  every observed offset and value matches the bytes;
- in IDB-write mode, approved structs and bitmask flags are declared and checked;
- COM interfaces have the right vtable order and only confirmed slots are named;
- every requested name and type was handled by its explicit operation and read back;
- approved changes were recompiled and checked;
- unmapped ordinals, unknown GUIDs, and version doubts are stated.
