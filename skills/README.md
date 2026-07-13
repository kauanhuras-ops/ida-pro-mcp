# IDA Pro MCP analysis skills

This set has ten analysis skills for work on an IDA database through MCP. Start with
`ida-re-methodology`. It sets the work scope and sends the task to a focused skill.

The skills target **IDA Professional 9.4** and **ida-pro-mcp 3.4.0**. Rules or examples
from older IDA versions are not a source of truth for this set.

## Stop-hook contract

A skill cannot invoke a slash command. Each `SKILL.md` therefore defines its own
prompt-based `Stop` hook in YAML frontmatter. Claude Code loads the hook only while that
skill is active. When the agent tries to stop, the hook checks the last response:

- `{"ok": true}` allows the agent to stop;
- `{"ok": false, "reason": "..."}` blocks the stop and gives the reason back as the next
  work instruction.

Each hook contains a short checklist for its skill. The final audit must mark every item
`pass`, `n/a`, or `blocked` and give evidence. The hook allows a stop only when every item
is proved or not applicable, or for a real blocker that needs user input, approval, or
external state. A progress note, TODO, failed check, unrun check, or unsupported “done”
claim is blocked.

The `/goal` command is an optional command that the user may run. Skills do not try to
invoke it. Claude Code implements `/goal` as a session prompt-based Stop hook, so the
skill hooks use the same supported hook type. They do not create session `/goal` state:
they are active only with the skill and judge the last audit against their fixed checklist.

## Common work rules

Every skill also follows these rules.

1. **State the working goal first.** Before any IDA or MCP tool call, write one short goal
   with the target, read-only or IDB-write scope, evidence needed, and clear done checks.
   Update it when the target or scope changes. This is a work record, not a `/goal` call;
   the Stop hook is the part that keeps the turn going.
2. **Use evidence in layers.** Treat decompiler output, auto-analysis, names, types, and
   comments as hypotheses. Use disassembly and raw bytes as the main static evidence.
   Check function bounds and instruction decoding when they are in doubt. A runtime
   observation is strong evidence for that run, but it does not prove all inputs or runs.
   Debug and diagnostic strings are naming evidence. When a string is tied to the same
   code or value by an xref, call argument, or data flow and exposes an original function,
   method, parameter, local, field, or global identifier, use its exact spelling instead
   of inventing a name and record the string address. State any ambiguity or conflict.
3. **Respect write scope.** A request to explain or review is read-only unless the user
   also asks for IDB changes. For approved IDB work, write only supported names, types,
   and comments. Record an uncertain idea as a `?` comment only when comments are in
   scope. Do not make a change only to meet a change count.
4. **Fix known conflicts.** If new evidence disproves an in-scope name, type, prototype,
   or field, fix it before using it as a base for more work. Recompile affected functions
   and check the result.
5. **Name and type with the right tools.** `rename` and `set_type` are separate operations.
   The preferred `set_type` edit always has `kind` and `ty`. Use `addr` for a function,
   local, or stack owner; use `variable` for an existing decompiler local; use `name` only
   as an existing global or stack-member locator. Use an explicit `rename` for a new name
   and read both facts back. If a local is renamed first, use its new name in the later
   type edit. `declare_stack` and `make_data` may create a name and type together.
6. **Cut tool round trips.** Use a tool's native list input for repeated work by that tool.
   Use `batch` for independent calls to different active tools. Keep dependent calls
   separate and check the first result before making the next call. `batch` accepts normal
   IDB writes but rejects debugger, Python, hidden-extension, and other `MCP_UNSAFE` tools.
   Treat `disasm.asm.lines` as one newline-delimited string and page it with `offset` and
   `max_instructions`; do not ask for or expect an array of instruction objects.
7. **Prefer known SDK and library types.** When an import, ordinal, GUID, COM vtable, or
   library function matches a known API, give it the real SDK name, prototype, structs, and
   flags one-to-one instead of a generic guess. IDA often names an import but does not apply
   its full type; close that gap. Use `ida-sdk-types` for Windows SDK, DirectX, and COM.
   Still confirm each struct against the observed offsets and widths.
8. **Report the result.** State what was checked, what changed, what evidence supports it,
   what remains uncertain, and whether every applicable done check passed.

## Hook limits and checks

The Stop hook is a guard, not an unlimited runner:

- it does not run after a user interrupt;
- API errors fire `StopFailure` instead of `Stop`;
- Claude Code ends the turn after eight consecutive Stop-hook blocks;
- the prompt judge checks the last completion report, not the IDB or transcript by itself,
  so the report must cover every checklist item with concrete evidence.

After loading a skill, use Claude Code's `/hooks` view to confirm that its prompt-based
`Stop` hook is active. The hook format follows the
[official Claude Code hook reference](https://code.claude.com/docs/en/hooks).

## Skills

| Skill | Scope | Use when |
|---|---|---|
| **ida-re-methodology** | Main workflow and router | Start of an analysis task |
| **ida-cold-start** | Fresh IDB survey and first targets | The database has little useful analysis |
| **ida-function-recon** | One function | Explain, name, or type one function |
| **ida-cluster-analysis** | A related function group | Map a subsystem or shared-data group |
| **ida-struct-recovery** | Structs, classes, unions, and vtables | Raw base-plus-offset accesses hide layout |
| **ida-cpp-rtti** | C++ classes from RTTI and constructors | Vtable writes, virtual calls, RTTI, or mangled names |
| **ida-sdk-types** | Windows SDK, DirectX, and COM types | An import, ordinal, GUID, or COM call matches a known API |
| **ida-decomp-verify** | Pseudocode checks | Hex-Rays output may be wrong or incomplete |
| **ida-calling-convention** | ABI, arguments, and return type | A prototype needs proof |
| **ida-dynamic-verify** | Debugger-based checks | Static evidence cannot settle a fact and the user has approved execution |

## Route

```text
ida-re-methodology
├── ida-cold-start
├── ida-function-recon
│   ├── ida-calling-convention
│   ├── ida-struct-recovery
│   │   ├── ida-cpp-rtti
│   │   └── ida-sdk-types
│   └── ida-decomp-verify
├── ida-cluster-analysis
│   └── focused skills for each member
└── ida-dynamic-verify
```

Dynamic work is unsafe and opt-in. Running a target needs clear user approval and a safe
test environment.
