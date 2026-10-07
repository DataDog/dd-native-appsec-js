# dd-native-appsec-js
Node.js bindings for [libddwaf](https://github.com/datadog/libddwaf).

# Supported platforms

This package supports the following platforms:

* **Node.js version:** 18 and higher
* **Operating Systems:**
  * macOS 14.2.1 and higher (the minimum target of the bundled libddwaf)
    * x64
    * arm64
  * Windows
    * x86
    * x64
  * Linux
    * x64 with glibc
    * x64 with musl
    * arm64

Therefore, unsupported platforms include:
* Linux x86
* arm32
* AIX
* PPC 

Please feel free to [contact support][support] if you would like to request support for a new platform.

[support]: https://docs.datadoghq.com/help

# Migrating to native-appsec 12

This version bundles libddwaf 2.1.0 and changes the evaluation API.
`context.run(data, timeout)` now receives an address map directly. The previous
`{ persistent, ephemeral }` envelope is no longer supported. For scoped data,
create a subcontext with `context.createSubcontext()`, call its `run(data, timeout)`
method, and dispose it in `finally`. A subcontext inherits parent data and keeps
its own data and evaluation effects local. It can outlive the parent.

`createContext()` returns `null` when there is no active ruleset, including after
removing all configurations. A rejected same-path replacement can also remove
the previous configuration; callers must check diagnostics and configuration
paths when deciding whether to restore a fallback ruleset.
If a rebuild produces no handle, new contexts also return `null`; the binding
does not distinguish an empty ruleset from other build failures or retain a stale handle.

`status: 'match'` can indicate attributes or actions without an attack event.
Check `events?.length` for rule events. Durations are nanoseconds; timeout inputs
are microseconds. Actions are a map keyed by action type.

## Responsibilities

| native-appsec | dd-trace-js |
| --- | --- |
| Native handles, allocators, finalizers and safe marshalling | Request and operation lifetimes, including explicit disposal |
| Context and subcontext evaluation primitives | Persistent/scoped input routing, evaluation order and shared timeout budgets |
| Raw results, diagnostics and truncation measurements | Result aggregation, blocking, reporting and telemetry |
| Configuration binding and argument validation | Remote Config orchestration, fallback policy and known-address filtering |

The dd-trace-js dependency upgrade must ship with the companion API migration.
Mixed persistent and scoped evaluations need explicit result aggregation and a
shared time budget in the tracer. The native binding does not infer those policies.

## Conversion and configuration limits

Evaluation data is limited to 4096 bytes per string, 256 entries per container,
20 levels of nesting, 5120 nodes and 1 MiB of retained key/value bytes per call.
String truncation preserves complete UTF-8 code points; byte buffers retain their
raw prefix. Truncation metrics report original sizes and whether the cumulative
node or byte limit was reached. dd-trace-js owns exporting those measurements.
Conversion follows property order and stops when either cumulative budget is
exhausted, so later addresses may be omitted. The flags report incomplete conversion.

Configuration is not subject to the request node/byte budgets. libddwaf 2.1's
large-container APIs support configuration arrays and maps beyond 65535 entries.

Obfuscator regex validation uses a temporary scanner because libddwaf 2.1.0 does
not expose obfuscator compilation failures in diagnostics. This configuration-only
workaround should be replaced when upstream provides those diagnostics.
An update rejected by this validation returns `false` and replaces `diagnostics`
with an empty object, since the update never reached the builder.
