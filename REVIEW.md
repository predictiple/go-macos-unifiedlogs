# Independent Review — Rust→Go Port (`go-macos-unifiedlogs`)

**Target:** `github.com/predictiple/go-macos-unifiedlogs` (root package `unifiedlogs` + `internal/sunlight`)
**Reference:** `reference/macos-UnifiedLogs` (Rust crate v0.7.0) and its `sunlight` v0.1.5 dependency
**Date:** 2026-10-07
**Method:** six-phase review per the agreed plan: (1) PoC harness in `/tmp` (repo untouched), (2) four-way Rust↔Go parity review, (3) README/doc.go/godoc accuracy, (4) test-quality spot checks, (5) golden Rust-vs-Go output diff on `tests/test_data`, (6) this report.

Every finding is tagged **Go-introduced** (the port diverges from Rust) or **inherited-from-Rust** (the port faithfully reproduces an upstream defect). Severity reflects impact; the tag reflects origin.

**Severity key**
- **Critical** — crash, hang, or unrecoverable failure reachable from untrusted log data.
- **Major** — panic on crafted input, material behavioral divergence, or significant test/docs gap.
- **Minor** — observable output divergence of low practical impact.
- **Nit** — wording, style, cosmetic.

**Harness artifacts** (outside the repo, reproducible):
- `/tmp/pocs/pkg` — copy of the package + `poc_test.go` PoCs (C1–C4, M1–M3, sockaddr, sunlight depth/O(N²))
- `/tmp/golden/rustdrv` — Rust driver (`cargo build --release`; `hangtest`, `iterhang`, `garbtest` bins)
- `/tmp/golden/godrv` — Go driver (`replace` → repo)
- `/tmp/golden/compare{,2,3}.py`, `msgcmp.py`, `msgdiff2.py` — canonical JSONL comparators
- `/tmp/golden/out/*_{rust,go}.jsonl` — 10,178,623 paired records across 6 logarchives

**Baseline (re-verified at report time):** `gofmt -l` clean, `go vet ./...` clean, `go test ./...` PASS (root + `internal/sunlight`).

**Post-fix updates (2026-10-07):** Applied fixes for #3 (AF_INET6 bounds guard), #4 (UUIDIndex uint64 comparison), #5 (catalog preallocation clamp), #1-#2 (chunk size wrap + progress guards), #6-#7 (bounds/order checks), #8 (sunlight depth cap), #11 (README cache prefilling). All changes committed.

---

## Summary

| # | Severity | Tag | Finding |
|---|----------|-----|---------|
| 1 | Critical | inherited-from-Rust | Infinite loop in `parseUnifiedLog` on crafted preamble (uint64 wrap + `paddingSize==0`) |
| 2 | Critical | inherited-from-Rust | Same infinite loop in `UnifiedLogIterator.Next` |
| 3 | Critical | Go-introduced | `getSockaddrData` AF_INET6 guard checks 22 bytes but reads 26 → panic |
| 4 | Critical | Go-introduced | `int(uint64 UUIDIndex)` wraps negative → `uuids[-1]` panic (3 sites) |
| 5 | Critical | Go-introduced | `make(..., 0, numberUUIDsEntries)` unbounded preallocation → fatal OOM |
| 6 | Major | inherited-from-Rust | `FormatFirehoseLogMessage` `itemIndex` out-of-range panic |
| 7 | Major | inherited-from-Rust | `checkObjects` off-by-one (`index > len`) → panic |
| 8 | Major | inherited-from-Rust | `internal/sunlight` unbounded recursion → fatal stack overflow |
| 9 | Major | inherited-from-Rust | `internal/sunlight` O(N²) parsing on nested protobuf |
| 10 | Major | Go-introduced | Zero unit tests for `firehose_log.go` + `firehose_message.go` (Rust has 32) |
| 11 | Major | Go-introduced | README: `CollectStrings`/`CollectSharedStrings` cannot prefill a `StringCache` |
| 12 | Minor | Go-introduced | Trace entries: `item` = `""` where Rust emits `"Unknown"` (19 records) |
| 13 | Minor | Go-introduced | Empty slices: JSON `null` where Rust emits `[]` (2,335,136 entries / 278,055 flags) |
| 14 | Minor | Go-introduced | `+Inf`/`-Inf` vs Rust `inf`/`-inf` in formatted messages (408 records) |
| 15 | Minor | Go-introduced | Top-level `time` float: JSON integer form vs Rust exponent form (all 10,178,623 records) |
| 16 | Minor | Go-introduced | Statedump JSON shape: sorted keys, `<`→`<`, `[]byte`→base64 |
| 17 | Minor | Go-introduced | Statedump plist dates differ by ≤ ~120 ns (howett f64 epoch add) |
| 18 | Minor | Go-introduced | `parseTime`: error wording + out-of-range timestamps handled differently |
| 19 | Nit | Go-introduced | Logger/decoder error wording differs from Rust in places |

Counts: **5 Critical, 6 Major, 8 Minor, 1 Nit.** Test totals: Go 223 `func Test` vs Rust 221 `#[test]`.

---

## Critical

### 1. Infinite loop on crafted chunk preamble — `unified_log.go:120` (inherited-from-Rust)

`parseUnifiedLog` loops `for len(input) != 0` (unified_log.go:120). A 16-byte preamble with `ChunkDataSize = 0xFFFFFFFFFFFFFFF0` makes:
- `chunkSize + chunkPreambleSize` (unified_log.go:128,131-132) wrap to **0** in uint64, so the length guard never trips and zero bytes are consumed;
- `paddingSize8` (util.go:33 → util.go:43, `return (alignment - (dataSize & (alignment-1))) & (alignment-1)`) return **0** for an already-8-aligned size, so `data = data[paddingSize:]` (unified_log.go:149-153) makes no progress and the `input = data` reassignment (unified_log.go:157) restarts on the same bytes.

The loop spins forever (CPU-bound), also flooding logs with "Unknown chunk type".

**Evidence:** PoC `TestPoC_C1_ParseUnifiedLogHang` / `TestPoC_C1_ParseLogHang` (`-test.timeout 5s` → `panic: test timed out`). **The Rust reference hangs identically**: `/tmp/golden/rustdrv/target/release/hangtest` (calls `parse_log` with the same bytes, release build) does not return within 5 s and spins at 100 % CPU (`utime` 200→300 ticks/s, state `R`). This is an upstream defect faithfully ported.

**Recommendation:** fix in the port with a checked add (`if chunkSize > maxUint64-chunkPreambleSize`) and require strict progress (`nextInput = data[padding:]`; `break` if `padding==0 && no bytes consumed`) — then upstream it.

### 2. Same infinite loop in `UnifiedLogIterator.Next` — `iterator.go:44` (inherited-from-Rust)

Identical mechanics: `loop:` at iterator.go:44, `nomBytes(input, chunkSize+chunkPreambleSize)` at iterator.go:54 (wraps to 0), `paddingSize := paddingSize8(...)` at iterator.go:75 (returns 0), no-progress iteration.

**Evidence:** PoC `TestPoC_C2_IteratorHang` times out; **Rust `UnifiedLogIterator` also hangs on the same input** (`/tmp/golden/rustdrv/target/release/iterhang`, exit 124 under `timeout 5`).

**Recommendation:** same as #1; add a shared progress guard in both loops.

### 3. `getSockaddrData` reads `rest[22:26]` behind a `< 22` guard — `network.go:117-123` (Go-introduced)

```go
case 30:                         // AF_INET6
    if len(rest) < 22 { ... }    // network.go:117  — insufficient
    ...
    scope := binary.BigEndian.Uint32(rest[22:26])  // network.go:123 — needs 26
```
A 24-byte sockaddr (base64-decodable, family 30, 22 bytes after the 2-byte header) passes the guard and panics: **`slice bounds out of range [:26] with capacity 22`**.

**Rust does not panic**: `decoders/network.rs::get_sockaddr_data` parses sequentially with nom (`be_u16, be_u32, get_ip_six, be_u32`); exhausted input returns `Err` → `DecoderError` "Failed to get sockaddr structure". This is a **regression against the reference**.

**Evidence:** PoC `TestPoC_SockaddrIPv6Panic`.

**Recommendation:** guard `len(rest) < 26` (and audit `getIPFour`/`getIPSix` bounds similarly).

### 4. `int(UUIDIndex)` wrap → negative index panic — `firehose_message.go:78, 122, 147` (Go-introduced)

```go
uuidIndex := int(sharedString.Ranges[0].UUIDIndex)   // firehose_message.go:78 (also 122, 147)
if uuidIndex >= len(sharedString.UUIDs) { ... }      // -1 passes this check
...
messageData.Library = sharedString.UUIDs[uuidIndex].PathString  // panic: index out of range [-1]
```
`UUIDIndex` is `uint64`; `0xFFFFFFFFFFFFFFFF` converts to `-1`, which passes the upper-bound guard.

**Rust is safe**: `message.rs:168-178` uses `uuid_index = ranges.uuid_index as usize` (unsigned; `usize::MAX >= uuid_len` is true) → logs "UUID index … out of bounds" and returns the diagnostic `"Error: Invalid UUID index"`. Go-introduced regression.

**Evidence:** PoC `TestPoC_C3_ExtractSharedStringsPanic` with a fake `StringCache` returning `UUIDIndex: 0xFFFFFFFFFFFFFFFF`.

**Recommendation:** compare as `uint64`: `if uint64(id) >= uint64(len(uuids))` before converting. Audit all three sites (the catalog indices are `uint16` and safe — catalog.go:321,328,393).

### 5. Unbounded preallocation → fatal OOM — `catalog.go:292` (Go-introduced)

```go
uuidInfoEntries := make([]ProcessUUIDEntry, 0, numberUUIDsEntries)  // catalog.go:292
```
`numberUUIDsEntries = 0xFFFFFFFF` (from a 40-byte crafted catalog process entry) makes `make` request a >100 GB backing array → **`fatal error: out of memory: cannot allocate 171798691840-byte block`** — unrecoverable, takes the process down.

**Rust handles it gracefully**: `catalog.rs:244` uses nom `many_m_n(...)`, whose implementation caps the initial allocation (`nom-8.0.0/src/multi/mod.rs:636-640`: `Vec::with_capacity(min.min(max_initial_capacity))`) and then fails on parse error with a normal `Err`.

**Evidence:** PoC `TestPoC_M3_CatalogHugeAllocation` under `ulimit -v 8000000`.

**Recommendation:** clamp the preallocation (e.g., `cap = min(numberUUIDsEntries, remainingBytes/minEntrySize)` or drop the capacity hint) and let the parse loop fail naturally.

---

## Major

### 6. `FormatFirehoseLogMessage` `itemIndex` panic — `message.go:133-141` (inherited-from-Rust)

The precision branch increments `itemIndex` (message.go:135) and the dynamic-precision check then dereferences `itemMessage[itemIndex]` (message.go:141) **before** the bounds check at message.go:146. Input `"%d"` with a single item of type `0x10` → **`index out of range [1] with length 1`**.

Rust has the same ordering defect: `message.rs:107-116` (`PRECISION_ITEMS` → `item_index += 1` → `item_message[item_index]` at line 112) with the bounds check only at line 119. Faithful port of an upstream bug.

**Evidence:** PoC `TestPoC_C4_FormatFirehoseLogMessagePanic`.

**Recommendation:** move the bounds check before both accesses; upstream the fix.

### 7. `checkObjects` off-by-one → panic — `decoder.go:49` (inherited-from-Rust)

```go
if index > len(messageValues) {   // decoder.go:49 — should be >=
```
`index == len` passes and the later `messageValues[index]` panics (`index out of range [1] with length 1` for `checkObjects("BOOL", vals, 0x12, 0)` with one value). Rust `decoders/decoder.rs:44` has the identical `if index > message_values.len()` — upstream bug reproduced exactly.

**Evidence:** PoC `TestPoC_M1_CheckObjectsPanic`.

**Recommendation:** `index >= len` in both ports (upstream too).

### 8. Unbounded recursion in `internal/sunlight` → fatal stack overflow — `sunlight.go:272` / `sunlight.go:300` (inherited-from-Rust)

`parseLengthTag` → `parseTag` → `parseLengthTag` … has no depth limit. A deeply nested protobuf (8 M levels, 47 MB) triggers **`fatal error: stack overflow`** (`goroutine stack exceeds 1000000000-byte limit`) inside `extractUTF8String`/`parseLengthTag`. The Go code is a faithful port of `sunlight-0.1.5` (`tags/length.rs:9` → `tags/parser.rs`), which likewise has no depth guard — Rust would abort with a stack overflow on the same input (static check; not executed).

**Evidence:** `/tmp/pocs/deep.test` run (`deep_crash.log`).

**Recommendation:** add a depth cap (e.g., 64–256) returning the `"Failed to get UTF8 string"`/base64 fallback; upstream.

### 9. O(N²) parsing of nested protobuf — `sunlight.go:284, 300-313` (inherited-from-Rust)

Every nesting level calls `extractUTF8String(valueData)` on the full length-delimited slice (`utf8.Valid` / copy), so a single large blob is re-scanned at every level: 20 KB → 7 ms, 96 KB → **4.5 s** (measured with the nested-protobuf harness `TestDepthProof` in `/tmp/pocs/pkg/bench_test.go`). Rust `utils/strings.rs::extract_utf8_string` does the same `data.to_vec()` per level (and shares the 2 MB base64 cap — sunlight.go:305-311 matches `strings.rs` exactly), so the complexity is inherited; the practical DoS amplification still matters for a service parsing untrusted archives.

**Recommendation:** validate UTF-8 only on leaf candidates or cache validity; upstream.

### 10. Zero unit tests for the two largest firehose files — Go-introduced

`firehose_log.go` (~850 lines) and `firehose_message.go` (~400 lines) have **no `_test.go` file at all**, while the Rust reference has **18** tests (`chunks/firehose/firehose_log.rs`) + **14** (`chunks/firehose/message.rs`). These files contain findings #3, #4, and the `parseFirehoseItems` state machine. The golden diff (below) exercised them indirectly on real data, but crafted-input paths (private items, backtraces, oversize firehose, sensitive items) have no regression net.

**Recommendation:** port the 32 Rust tests first; they map 1:1.

### 11. README documents cache prefilling that does not exist — `README.md:122-124` (Go-introduced)

> "`CollectStrings` and `CollectSharedStrings` prefill it; otherwise entries are loaded lazily on first use via `GetOrLoadUUIDText`/`GetOrLoadDSC`."

`CollectStrings(provider)` (parser.go:34) and `CollectSharedStrings(provider)` (parser.go:60) take **no cache parameter** and return slices; `MemoryStringCache` exposes only `GetOrLoadUUIDText` (cache.go:37) and `GetOrLoadDSC` (cache.go:61) — there is no way for these functions to prefill anything, and no public setter to prefill manually. The documented performance pattern is unusable as written. (All other README claims checked — error sentinels error.go:17-23, diagnostic strings firehose_message.go:156/169, message.go:117/148, `excludeMissing` behavior — are accurate.)

**Recommendation:** either add `AddUUIDText`/`AddDSC` to the cache interface (and have the Collect* functions optionally fill it), or rewrite the README section to describe lazy-only loading.

---

## Minor (golden-output divergences unless noted)

All items below were measured on real archives by streaming paired JSONL from the Rust driver and the Go driver (see **Golden diff** for method).

### 12. Trace entries serialize `item` as `""` instead of `"Unknown"` — `trace.go:95`, `firehose_log.go:66-77` (Go-introduced)

`parseTraceMessage` builds `FirehoseItemType` with only `MessageStrings` set (trace.go:95). Rust relies on `FirehoseItem`'s `#[default] Unknown` (firehose_log.rs:89-100) so serde emits `"Unknown"`; Go's `type FirehoseItem string` zero value marshals as `""`. `FirehoseItemUnknown` (firehose_log.go:77) is defined but never assigned.
**Measured:** 19 records across 10,178,623 (all High Sierra trace entries).
**Fix:** `MarshalJSON` on `FirehoseItem` mapping `""`→`"Unknown"`, or set `FirehoseItemUnknown` at construction.

### 13. Nil slices serialize as `null` instead of `[]` — `unified_log.go:98, 100` (Go-introduced)

`message_entries` / `message_flags` are only assigned for certain event types; otherwise they are nil → Go `encoding/json` emits `null`, Rust `Vec<T>` emits `[]`.
**Measured:** 2,335,136 `message_entries` + 278,055 `message_flags` records differ (shape only; content otherwise identical).
**Fix:** initialize to `[]FirehoseItemType{}` / `[]MessageFlags{}` (or `json:",omitempty"` — but `[]` matches Rust better).

### 14. `+Inf`/`-Inf` vs Rust `inf`/`-inf` — `message.go:511, 560` (Go-introduced)

`strconv.FormatFloat(item, 'f', …)` renders infinities as `"+Inf"`/`"-Inf"`; Rust `format!("{:.…}")` emits `inf`/`-inf`. Example (golden): `bb_want_unc_s,+Inf,want_unc_s,0.05,…` vs Rust `…,inf,…`.
**Measured:** 408 records across 6 archives.
**Fix:** special-case `math.IsInf` → `"inf"`/`"-inf"`.

### 15. Top-level `time` float JSON form — `unified_log.go:88` (Go-introduced)

Rust serde_json/ryu writes epoch-ns as `1.6241348115460605e+18`; Go writes `1624134811546060500`. **Numerically identical on every one of 10,178,623 records** (verified with float-normalized comparison: 0 value mismatches). Any JSON parser sees the same number; only byte-for-byte diffs and naive string comparisons are affected. Fix only if bit-identical output is a goal (custom `MarshalJSON`).

### 16. Statedump JSON serialization shape — `statedump.go:176` (Go-introduced)

`json.Marshal(results)` (encoding/json) vs Rust `serde_json::to_string(&plist::Value)`:
- **key order:** Go sorts map keys; Rust preserves plist insertion order (hundreds of records per archive);
- **HTML escaping:** Go escapes `<`/`>`/`&` (a value `<null>` is emitted in JSON as `"\u003cnull\u003e"`); Rust does not;
- **binary plist `<data>`:** Go `[]byte` marshals to base64 (`"AwAGAQ=="`); Rust `plist::Value::Data` marshals to a byte array (`[3,0,6,1]`) — e.g., `/expressMode/rfModifierTCIs`, `/config_store/BasisRefTimeData`.
Embedded JSON was otherwise **structurally equal** in every differing record (84/84 High Sierra, 186+6 Big Sur, 279+6 Monterey, 2240+97 Tahoe — residual diffs are the date issue below).
**Fix (if parity is required):** decode into ordered structures and marshal with `json.Encoder` + `SetEscapeHTML(false)`, or convert `[]byte` to `[]int` before marshal.

### 17. Statedump plist dates differ by ≤ ~120 ns — `statedump.go:172` + dependency (Go-introduced)

Example: Rust `2025-06-22T17:10:00.674980998Z` vs Go `…674981117Z` (+119 ns). Root cause: binary plist dates are f64 seconds since 2001; `howett.net/plist@v1.0.1/bplist_parser.go:234` does `val += 978307200` in f64 (ulp ≈ 119 ns at that magnitude) then truncates, whereas Rust `plist` keeps the f64 fractional part separate and converts with `Duration::try_from_secs_f64` (near-exact). Differences observed: ±1 ns … ±120 ns — consistent with the ulp analysis.
**Fix:** not practical in-dep; document, or post-process dates if sub-µs parity matters (it does not for log analysis).

### 18. `parseTime` error and range behavior — `time.go:17-31` (Go-introduced)

- Error wording: Go `"Failed to parse time string to int"` vs Rust `"Failed to parse timestamp"` (`decoders/time.rs:19`).
- Out-of-range: Rust `Utc.timestamp_opt` rejects unrepresentable timestamps (returns `DecoderError`); Go `time.Unix(timeInt, 0)` accepts any int64 and formats far-out-of-range years instead of erroring. Unreachable with well-formed data (RFC3339 millisecond output matches: both `…T15:04:05.000Z`).

### 19. Logger/decoder error wording (Nit)

Various log strings differ from Rust (e.g., Go `"Failed to nom chunk bytes"`, `"Failed to parse time string to int"`). Not observable in `LogData` output; noted for completeness.

---

## Golden diff (Phase 5) — full results

**Method.** Two drivers run the identical pipeline over the same archive:
`provider.tracev3_files()` → `parse_log`/`ParseLog` → `build_log`/`BuildLog(exclude_missing=false)` → one JSON object per `LogData` record, in provider order. Rust: `serde_json::to_writer`; Go: `json.Encoder`. Compared with a streaming comparator that (a) requires equal line counts, (b) field-compares, (c) treats numeric-notation-only differences separately, (d) parses embedded statedump JSON and compares structurally.

| Archive | Records (both) | Equal except noted classes |
|---|---:|---|
| system_logs_high_sierra | 569,796 | ✓ |
| system_logs_big_sur | 747,616 | ✓ |
| system_logs_monterey | 2,397,109 | ✓ |
| system_logs_big_sur_private_enabled | 887,890 | ✓ |
| system_logs_big_sur_public_private_data_mix | 1,287,628 | ✓ |
| system_logs_tahoe | 4,288,584 | ✓ |
| **Total** | **10,178,623** | |

**Verified identical:** record counts; record ordering (line-aligned across all 6 archives); `LogData.time` numeric values (10,178,623/10,178,623 after float normalization); `timestamp` strings; message formatting incl. all privacy placeholders (`<private>`, `(null)`, base64 private data — zero divergences in the two private-data archives); `log_type`/`event_type`; catalog/UUID/process fields; backtrace; missing-message diagnostics; all non-listed fields (zero differences bucket-wide).

**Divergence classes (complete):** #12 `item` ""/Unknown (19 records), #13 null/`[]` (2,613,191 records), #14 inf notation (408), #15 float notation (all), #16 statedump JSON shape (hundreds), #17 statedump dates ≤120 ns (dozens). No other field differs anywhere.

**Error-path probes (API level):** random garbage, huge-chunk preamble, empty input, truncated mid-stream — Go and Rust return byte-identical outcomes (same error string / same `Ok` partial result) in all four probes.

---

## Test suite assessment (Phase 4)

- **Totals:** Go 223 `func Test` vs Rust 221 `#[test]` — broad parity.
- **Gap:** findings #10 (0 vs 32 tests for `firehose_log.go`/`firehose_message.go`).
- **Fixture transcription spot-checks (Go vs Rust constants):** `chunkset` (`0x600d`, subtag 17, data size 21703, signature 825521762, uncompress 63560, block 21687, footer 607417954) ✓; `catalog` (`0x600b`, 464, earliest firehose 820223379547412) ✓; `uuidtext` (signature `0x66778899`, versions 2/1, entries 2, sizes 617/2301, ranges 32048/29747, footer 2987) ✓; `timesync` (5 records) ✓. No transcription errors found in sampled files.
- Regex parity (`message.go` firehose regex vs `unified_log.rs:143` production copy) and format-loop ordering were verified earlier in the parity phase: Go matches production Rust.
- Baseline suite: PASS (`go test ./...`), `gofmt -l` clean, `go vet ./...` clean.

---

## Recommended fix order

1. **#4, #3, #5** (Go-introduced criticals): bounds/checked-allocation fixes — small, unambiguous, regression-testable.
2. **#10**: port the 32 Rust firehose tests — they cover the files owning #3/#4.
3. **#1, #2, #6, #7, #8**: progress guards + off-by-one fixes (also upstream PRs to mandiant/macos-UnifiedLogs and sunlight).
4. **#11**: README/API for cache prefilling.
5. **#12–#14, #16**: cheap JSON-output parity fixes if byte-level parity with Rust output is a goal; otherwise document the divergences (the golden comparator in `/tmp/golden` can re-verify).
6. **#9, #15, #17, #18, #19**: document; fix only if a consumer contract requires it.
