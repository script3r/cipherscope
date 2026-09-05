# Pattern configuration

The supported schema is `"1"`. The optional `[version]` table accepts `schema`
and `updated`; files without version metadata continue to use schema 1.
Unknown fields, unsupported schema versions, empty names, empty language lists,
duplicate library names, and unknown language names are errors. Regex diagnostics
identify the owning library, algorithm, and parameter where applicable.

Recognized language names are `C`, `C++`, `Java`, `Python`, `Go`, `Swift`, `PHP`,
`ObjC`, `Rust`, `JavaScript`, and `TypeScript`. They remain valid in configuration
when their Cargo features are disabled. `Kotlin` and `Erlang` are reserved names
already used by the bundled catalog; their definitions are validated but scanning
is unavailable until parsers are implemented.

Library tables accept `name`, `languages`, `patterns`, and `algorithms`.
`[library.patterns]` accepts `include` and `apis`. Algorithm tables accept `name`,
`primitive`, `nistQuantumSecurityLevel`, `symbol_patterns`, and
`parameter_patterns`. Parameter tables accept `name`, `pattern`, and
`default_value`.

Parameter extraction reads capture group 1. A regex with no capture group cannot
extract a value; a configured `default_value` is used when extraction fails.
Multiple definitions of the same algorithm or parameter remain allowed because
the bundled catalog uses them for alternative signatures. The
`nistQuantumSecurityLevel` field is currently parsed but is not emitted in findings.
