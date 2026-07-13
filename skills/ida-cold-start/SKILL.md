---
name: ida-cold-start
description: Build a sound first map of a fresh or weak IDA database. Use to wait for analysis, find real entry paths, type imports, choose first targets, and find evidence for dynamic data types.
hooks:
  Stop:
    - hooks:
        - type: prompt
          prompt: >-
            Decide whether Claude may stop the active ida-cold-start task. Review
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

# Cold start

## Goal and stop contract

Before any IDA or MCP tool call, set the working goal: survey the named binary in the
requested read-only or IDB-write mode; finish when entry paths, checked boundary types,
first targets, and open risks are recorded.

Update the working goal if the target becomes one subsystem or function. Keep working
until the done checks pass. Ask before an IDB change when write authority is not clear.

The frontmatter `Stop` hook checks the last response. Before a final response, include a
short completion audit with the target, write scope, checks run, results, and remaining
work. If required work remains, the hook blocks stopping and returns the next work.

## Evidence rule

Treat auto-analysis, decompiler output, names, types, and comments as hypotheses. Use
disassembly, raw bytes, file metadata, imports, and xrefs as static evidence. Check
function bounds and code/data classification when they look wrong.

## 1. Make one survey

1. Use `server_health` and wait until IDA auto-analysis is ready.
2. Use `survey_binary` once. Record architecture, bitness, image base, segments, entry
   points, imports, exports, high-xref strings, and high-use functions.
3. Detect the platform before using an ABI or allocator list. The Windows names below are
   examples, not a rule for every binary.

Do not call `list_funcs`, `imports`, and `find_regex` only to rebuild data already returned
by `survey_binary`.

## 2. Find execution entry paths

Do not use only `main` or `WinMain`. Check the entry data that applies to the file:

- program entry and exports;
- TLS callbacks;
- C or C++ initializer tables;
- service, plugin, driver, or library entry points;
- registered callbacks, thread procedures, message handlers, and indirect dispatch.

Use imports, strings, xrefs, and call sites to find these paths. Mark a path as confirmed
only when its registration or entry evidence is visible.

## 3. Fix boundary types

Known external prototypes give useful types to callers.

1. Query used imports with `imports_query`.
2. Check any thunk or local wrapper in disassembly.
3. In IDB-write mode, name first and then apply the type (see below), using supported
   prototypes with `set_type`.
4. Call `force_recompile` for affected callers and read them again.

Go past bare names. IDA often names an import but does not apply its full SDK type. When an
import, an ordinal import, a COM creation call, or a GUID matches a known Windows SDK,
DirectX, or COM API, route to **ida-sdk-types** to give it the real prototype, structs, and
flags one-to-one. This turns `*(a1 + 8)` into `desc->dwFlags` across every caller.

**Rename before type.** Naming and typing are separate operations in IDA. For the same
import, thunk, or wrapper, run `rename` first, then `set_type`, as separate steps, and check
that the name survived.

Do not apply a platform prototype from memory when the binary's ABI or library version is
not known.

## 4. Choose first targets

Rank targets by evidence and effect:

1. entry paths and exports;
2. functions tied to clear strings or imports;
3. high-use local wrappers and leaf functions;
4. functions that own shared globals or context pointers;
5. dispatchers and higher-level code after their callees are known.

A name must have support from strings, imports, constants, xrefs, call behavior, or an
approved runtime observation. If the role is still uncertain, keep the current name and
state the hypothesis in the report. Add a `?` comment only in approved write mode.

## 5. Find allocation sites

Allocation sites can give size bounds and object-life evidence. They do not prove a C
layout by themselves.

### Find allocator families

On Windows, check names such as `malloc`, `operator new`, `HeapAlloc`, `VirtualAlloc`,
`LocalAlloc`, `GlobalAlloc`, and `CoTaskMemAlloc`. Use the matching family for other
platforms.

1. Find raw allocator imports and their xrefs.
2. Read common local wrappers. Confirm a wrapper by its call or tail-call behavior and
   return value, not only by its place in the call graph.
3. Query all direct call sites to the confirmed raw allocators and wrappers. Note that
   indirect calls and inlined allocators may need other evidence.

### Classify the size expression

- A constant request is a fixed-size allocation candidate. It equals `sizeof(T)` only
  when the call makes one complete `T` object and the wrapper adds no header, trailer,
  array, or extra capacity.
- A product such as `count * stride` is an array candidate. The stride may be the element
  size; verify how the returned pointer is indexed.
- A variable size is often a buffer or a type with variable trailing data.

Do not rank only by byte size. Small nodes and headers may be more useful than large
buffers.

### Recover use of the returned pointer

For each useful site:

1. Read the call site and identify the returned pointer.
2. Follow where it is stored and where that stored value is read.
3. Record each constant offset, access width, and use.
4. Treat `max(offset + width)` as a lower bound on accessed extent, not the full object
   size.
5. Route the layout work to **ida-struct-recovery**.

In write mode, apply a partial type only for fields that have evidence. Recompile owners
and check that later offsets still match.

## Dynamic check

If static evidence cannot settle a load-bearing size, offset, or indirect target, use
**ida-dynamic-verify** only after explicit user approval to run the target. An observed
allocation request proves that request for that run. It may still include capacity,
headers, or trailing data.

## Done

Finish only when:

- auto-analysis is ready and the platform and ABI are stated;
- all relevant entry paths found in the requested scope are listed with evidence;
- in-scope external boundaries have checked prototypes;
- the first analysis targets are ranked with a reason;
- each claimed allocation object has its allocator path, size expression, and pointer-use
  evidence;
- approved IDB changes were recompiled and read back;
- open uncertainty and paths not yet reached are stated.
