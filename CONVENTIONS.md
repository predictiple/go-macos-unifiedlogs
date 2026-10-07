# Go Port Conventions (go-macos-unifiedlogs)

This repository ports the Rust crate `mandiant/macos-UnifiedLogs` to Go. It is a
library only (no CLI). The Rust source is checked out under
`reference/macos-UnifiedLogs/` (gitignored). Port each `.rs` file into a Go file
of the same base name (`.go`) at the package root, faithfully reproducing
behavior. Do NOT redesign; match the Rust logic exactly.

## Package layout

- Package `unifiedlogs` at module root. Module `github.com/predictiple/go-macos-unifiedlogs`, Go 1.26.
- `internal/sunlight` holds the port of `puffyCid/sunlight` (`extract_protobuf`) for later phases.
- No third-party deps except `github.com/pierrec/lz4/v4` and `howett.net/plist`.

## Naming & types

- Struct names keep the Rust `PascalCase` name (e.g. `FirehoseActivity`).
- Field names keep Rust field names in `CamelCase` (e.g. `pub log_activity_type` -> `LogActivityType`).
  Preserve Rust typos verbatim, e.g. FirehosePreamble.`Unkonwn2`, `ContinousTimeDelta`.
- Every serialized field gets a `json:"snake_case"` tag mirroring the Rust serde field name.
- Enums become `type X string` with `const` values named `X<Value>`; the string value equals the Rust
  variant name (e.g. `FirehoseItemString FirehoseItem = "String"`, `TS MessageFlags = "TS"`). Rust
  enum serde output uses the bare variant name (`#[derive(Serialize)]`, no rename_all).
- Functions: `pub fn` -> exported `CamelCase`; `fn` (private) -> unexported `camelCase`.
  Prefix unexported parsers with the thing they parse only when it aids clarity.
- `Vec<T>` -> `[]T`, `String` -> `string`, `u8/u16/u32/u64` -> `uint8/uint16/uint32/uint64`,
  `i8..i64` -> `int8..int64`, `Vec<u8>` byte arrays stay `[]byte`.

## nom -> Go mapping

- nom `le_u8/le_u16/le_u32/le_u64/le_i8/le_i16/le_i32/le_i64` -> `cursor` methods
  `c.u8()/u16()/u32()/u64()/i8()/i16()/i32()/i64()` returning `(T, error)`.
- `Cursor.takeWhile(fn)` mirrors `take_while`. `c.rest()` is the remaining input.
- When a Rust parser needs to return the *remaining* input as well as a value (nom `IResult<&[u8], T>`),
  the Go function returns `(remaining []byte, value T, err error)`. Prefer explicit slice
  helpers in files where the Rust code sub-slices heavily:
  - `nomTake(data []byte, n uint64) (remaining, taken []byte, err error)` mirrors
    `nom::bytes::complete::take` and returns a `%w`(ErrEof) error when `n > len(data)`
    (nom returns `ErrorKind::Eof`).
  - `nomTakeWhile(data []byte, fn) (remaining, taken []byte)` mirrors `take_while` (never errors).
- Missing input on cursor scalar reads -> error (wraps `ErrEof`). This is a deliberate fidelity
  compromise: nom distinguishes `Err::Incomplete` vs `Error(Eof)`; we use `ErrEof`/`ErrIncomplete`
  sentinels only where tests care, otherwise any error propagates identically.
- The `?` operator on a nom result -> `if err != nil { return ..., err }` (propagate). 
- `let _ = expr()` where expr returns a result -> assign to `_` and IGNORE the error (e.g. `_, _ = parsePrivateFirehoseData(...)`).
- `take_while`/`map`/`many_m_n` loops that nom "count" scalars: read the count with a cursor, then loop.
- `u64_to_usize` -> `u64ToUint`; on None log and return a `%w`(ErrTooLarge) error, like Rust's
  `ErrorKind::TooLarge` branch.
- `format!("{x}")` etc. -> `fmt.Sprintf`. `format!("{value:X}")` on u128 -> minimal uppercase hex
  (no zero padding) via `fmt.Sprintf("%X", new(big.Int).SetBytes(v[:]))`.
- `mapping_rust_flags`: flag constants are untyped; use `uint16` masks as in Rust.

## Errors

Sentinels live in cursor.go: `ErrIncomplete`, `ErrEof`, `ErrFail`, `ErrTooLarge`.
`ParserError` (error.go) is for path/signature mismatches. Wrap with `fmt.Errorf("...: %w", sentinel)`.

## Logging

Use std `log`. Keep the literal prefixes from Rust, e.g. `[macos-unifiedlogs] Unknown Firehose item: %d`.
Strip `{data:?}`/`{data:X?}` debug payloads or log them as `%x` when cheap.

## Tests

- Port the Rust unit tests in the bottom of each `.rs` file (`#[cfg(test)]`) as Go table/case tests
  in a `_test.go` file of the same name.
- Embedded fixture byte arrays from Rust tests must ALWAYS run (copy them into the test).
- File-based fixtures (`tests/test_data/...`) are gated:
  start the test with `requireTestData(t, "relative/path")` (skips when the archive is absent, since
  we do not download the 503MB dataset). See `testdata_test.go`.
- Rust asserts like `assert_eq!` on struct fields -> `reflect.DeepEqual` or field-by-field.
- Assertions: use stdlib `testing` only; no testify.

## Integration contract (IMPORTANT - match exactly)

These types/functions are shared across files. Sub-agent ports MUST compile against them:

- `FirehoseItem` enum: values
  `FirehoseItemString "String"`, `FirehoseItemPrivateNumber "PrivateNumber"`,
  `FirehoseItemNumber "Number"`, `FirehoseItemPrivateString "PrivateString"`,
  `FirehoseItemPrecision "Precision"`, `FirehoseItemSensitive "Sensitive"`,
  `FirehoseItemObject "Object"`, `FirehoseItemSensitiveNumber "SensitiveNumber"`,
  `FirehoseItemUnknown "Unknown"` (default, matches `#[default]`).
- `FirehoseItemType{ItemType uint8; ItemTypeSize uint8; Offset uint16; ItemSize uint16; MessageStrings string; Item FirehoseItem}`.
- `FirehoseItemData{ItemInfo []FirehoseItemType; BacktraceStrings []string}`.
- `MessageFlags` string type with the 19 variants from firehose_log.rs:
  `SharedCache, MainExe, HasLargeOffset, LargeSharedCache, Absolute, UuidRelative, MainPlugin,
  PcStyle, HasUniquePid, HasCurrentAid, HasOtherAid, HasRules, HasName, AltIndex, Unknown,
  HasPrivateData, HasOversize, HasSubsystem, HasPersona`. One package-wide type; message.rs uses
  the same type in Phase 3b.
- `Firehose` struct (firehose_log.go) holds: `LogActivityType, LogType, Flags, FormatStringLocation,
  ThreadID, ContinousTimeDelta, ContinousTimeDeltaUpper, DataSize, FirehoseActivity,
  FirehoseNonActivity, FirehoseLoss, FirehoseSignpost, FirehoseTrace, Item, NumberItems,
  MessageFlags []MessageFlags, Message FirehoseItemData`.
- Leaf parser signatures (implemented in the sub-agent files, called by firehose_log.go):
  - `parseActivity(data []byte, flags uint16, logType uint8) ([]byte, FirehoseActivity, error)`
  - `parseNonActivity(data []byte, flags uint16) ([]byte, FirehoseNonActivity, error)`
    - REQUIRED FIELDS on FirehoseNonActivity: `PrivateStringsSize uint16`, `PrivateStringsOffset uint16`.
  - `parseSignpost(data []byte, flags uint16) ([]byte, FirehoseSignpost, error)`
  - `parseFirehoseLoss(data []byte) ([]byte, FirehoseLoss, error)`
  - `parseFirehoseTrace(data []byte) ([]byte, FirehoseTrace, error)`
    - REQUIRED FIELD on FirehoseTrace: `MessageData FirehoseItemData`.
- FirehoseItemData default zero value: describe the log message fields for Firehose struct tests.

## Delegation rule

firehose_log.go, catalog.go, lzbitmap.go, chunkset.go, message.go, unified_log.go and the
iterator/parser/cache/filesystem/traits.go files are ported by the lead agent. The sub-agent session
that owns activity/nonactivity/signpost/loss/trace/flags and oversize/statedump/simpledump must NOT
modify firehose_log.go or cursor.go. It may read them.