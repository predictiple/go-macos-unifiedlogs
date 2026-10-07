# go-macos-unifiedlogs

A cross-platform Go library to parse Apple Unified Logs (`tracev3`) from a live macOS
system or from a collected logarchive.

This is a Go port of the Rust crate
[`mandiant/macos-UnifiedLogs`](https://github.com/mandiant/macos-UnifiedLogs). No Apple
APIs are used, so it parses Unified Log data on any platform.

API reference: [pkg.go.dev/github.com/predictiple/go-macos-unifiedlogs](https://pkg.go.dev/github.com/predictiple/go-macos-unifiedlogs).

## Install

```sh
go get github.com/predictiple/go-macos-unifiedlogs
```

## Usage

A unified log bundle is spread across several files, so parsing happens in stages:

1. Collect auxiliary string and time data with `CollectTimesync`, `CollectStrings`,
   and `CollectSharedStrings`.
2. Read each `.tracev3` file and iterate its chunks, either via `ParseLog` (one reader
   to one `*UnifiedLogData`) or by driving `UnifiedLogIterator` directly.
3. Resolve each chunk into log records with `BuildLog`, passing a `FileProvider`, a
   `StringCache`, and the timesync data from step 1.

```go
provider := unifiedlogs.NewLogarchiveProvider("/path/to/system_logs.logarchive")
cache := unifiedlogs.NewMemoryStringCache()

timesyncData, err := unifiedlogs.CollectTimesync(provider)
if err != nil {
	log.Fatal(err)
}

// Oversize entries hold large strings that do not fit in a normal log record and
// must be carried forward across chunks.
oversize := &unifiedlogs.UnifiedLogData{}
for _, entry := range provider.Tracev3Files() {
	r, err := entry.Reader()
	if err != nil {
		log.Fatal(err)
	}
	data, err := io.ReadAll(r)
	r.Close()
	if err != nil {
		log.Fatal(err)
	}

	it := &unifiedlogs.UnifiedLogIterator{
		Data:     data,
		Evidence: entry.SourcePath(),
	}
	for {
		chunk, ok := it.Next()
		if !ok {
			break
		}
		chunk.Oversize = append(chunk.Oversize, oversize.Oversize...)
		logs, missing := unifiedlogs.BuildLog(chunk, provider, cache, timesyncData, true)
		oversize.Oversize = chunk.Oversize
		log.Printf("%s: %d log entries", entry.SourcePath(), len(logs))
		_ = missing
	}
}
```

## Providers

Two `FileProvider` implementations ship with the library:

- `NewLiveSystemProvider()` reads from a running macOS system.
- `NewLogarchiveProvider(path)` reads from an extracted `system_logs.logarchive` directory.

Callers may implement `FileProvider` and `SourceFile` to supply data from arbitrary
formats. `NewMemoryStringCache()` provides the default `StringCache`.

`NewLiveSystemProvider()` reads the running system's log paths, so on macOS the process
needs Full Disk Access (or to run as root). The logarchive provider has no such
requirement and works on any OS.

## Understanding the output

`BuildLog` returns `[]LogData`. Each record carries the message in three forms:

- `Message` — the fully formatted, privacy-redacted string shown by `log`/Console.
  Private values are replaced with `<private>`, and missing data with
  `<Missing message data>`.
- `RawMessage` — the format template before arguments are substituted, e.g.
  `"dlsym cannot find symbol %{public}@ in %{public}@: %s"` (privacy annotations such as
  `%{private}` are preserved here).
- `MessageEntries` — the resolved arguments, one `FirehoseItemType` per format slot.

Other useful fields: `Time` (nanosecond wall-clock as `float64`), `Timestamp` (RFC 3339),
`EventType`/`LogType`, `PID`/`EUID`/`ThreadID`, `Process`/`Library` and their UUIDs, and
`Evidence` (the source `.tracev3` path). Every field has a `json` tag, so records can be
marshalled directly.

## Logging

The library is silent by default: diagnostics ported from the Rust crate's
`debug!`/`warn!`/`error!` macros are discarded. To surface them, route them to a writer:

```go
unifiedlogs.SetLogOutput(os.Stderr)
// or: unifiedlogs.SetLogOutput(io.Discard) // silence again
```

## Errors

`ParseLog`, `CollectTimesync`, `CollectStrings`, and `CollectSharedStrings` return
`ParserError` sentinels (`ErrPath`, `ErrDir`, `ErrTracev3Parse`, `ErrRead`, `ErrTimesync`,
`ErrDsc`, `ErrUUIDText`). Note that malformed *individual* records are not returned as
errors: they appear in the output with a diagnostic `Message`, such as
`"Error: Invalid shared string offset"`, `"Unknown shared string message"`, or
`"<Missing message data>"`. Filter these when consuming results if you need clean data.

## Performance and caching

A `StringCache` resolves UUIDText and DSC (shared cache) lookups. Entries are loaded lazily on first use via
`GetOrLoadUUIDText`/`GetOrLoadDSC`. Reuse one cache across every file in a bundle so
lookups are not repeated.

A full logarchive can produce millions of records (tens of millions of entry items), so
prefer streaming or aggregating results rather than holding them all in memory. When
`excludeMissing` is true, `BuildLog` also returns the entries it skipped as missing data,
which callers may want to log or persist.

## Compatibility

This is a Go port of the `mandiant/macos-UnifiedLogs` Rust crate. It parses Unified Log
data collected from macOS 10.13 (High Sierra) through macOS 26 (Tahoe); the bundled
integration fixtures cover those releases. The API is not yet semver-stable.

## Testing

Most tests are self-contained and pass offline. Integration tests that exercise real
`system_logs.logarchive` captures read from `tests/test_data` and skip when that data
is absent. To run them, download `test_data.zip` from the upstream
[v1.0.0 release](https://github.com/mandiant/macos-UnifiedLogs/releases/download/v1.0.0/test_data.zip)
and extract it so that files land under `tests/test_data/`.

```sh
go test ./...
```

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).

This is a derived work of
[mandiant/macos-UnifiedLogs](https://github.com/mandiant/macos-UnifiedLogs), which is
likewise Apache-2.0 licensed, and includes its `internal/sunlight` protobuf parser.