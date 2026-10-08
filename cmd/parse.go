package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	kingpin "github.com/alecthomas/kingpin/v2"
	unifiedlogs "github.com/predictiple/go-macos-unifiedlogs"
	"github.com/predictiple/go-macos-unifiedlogs/filtering"
	"www.velocidex.com/golang/vfilter"
	"www.velocidex.com/golang/vfilter/types"
)

var (
	parse_command = app.Command(
		"parse", "Parse files.")

	parse_command_file_arg = parse_command.Arg(
		"directory", "The logarchive directory",
	).Required().String()

	parse_command_filter = parse_command.Flag(
		"filter", "A VQL Filter to eliminate rows").String()

	parse_command_format = parse_command.Flag("format",
		"Output format (jsonl, json)").Default("jsonl").String()
)

func doParse() (err error) {
	if *verbose_flag {
		unifiedlogs.SetLogOutput(os.Stderr)
	}

	var printer func(l interface{})
	switch *parse_command_format {
	case "", "jsonl":
		printer = jsonlRowPrinter
	case "json":
		printer = jsonRowPrinter
	default:
		return fmt.Errorf("Unsupported output format %v", *parse_command_format)
	}

	ctx, cancel := Install_sig_handler()
	defer cancel()

	var (
		scope      vfilter.Scope
		vql_filter *vfilter.VQL
	)

	if *parse_command_filter != "" {
		vql_filter, err = vfilter.Parse("SELECT * FROM plugin() WHERE " + *parse_command_filter)
		if err != nil {
			return err
		}

		scope = filtering.NewScope()
	}

	provider := unifiedlogs.NewLogarchiveProvider(*parse_command_file_arg)
	cache := unifiedlogs.NewMemoryStringCache()

	timesyncData, err := unifiedlogs.CollectTimesync(provider)
	if err != nil {
		return err
	}

	// Oversize entries hold large strings that do not fit in a normal log record and
	// must be carried forward across chunks.
	oversize := &unifiedlogs.UnifiedLogData{}
	for _, entry := range provider.Tracev3Files() {
		r, err := entry.Reader()
		if err != nil {
			return err
		}
		data, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			return err
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
			_ = missing

			for _, l := range logs {
				// Evaluate the filter on the row and only allow
				// it when it matches.
				if scope != nil &&
					!filterLog(ctx, scope, vql_filter, &l) {
					continue
				}

				printer(filtering.WrapLogData(&l))

				select {
				case <-ctx.Done():
					return errors.New("Cancelled!")
				default:
				}
			}
		}
	}

	return nil
}

func jsonlRowPrinter(log interface{}) {
	serialized, err := json.Marshal(log)
	if err == nil {
		fmt.Printf("%v\n", string(serialized))
	}
}

func jsonRowPrinter(log interface{}) {
	serialized, err := json.MarshalIndent(log, " ", " ")
	if err == nil {
		fmt.Printf("%v\n", string(serialized))
	}
}

func filterLog(
	ctx context.Context, scope types.Scope,
	vql_filter *vfilter.VQL,
	log *unifiedlogs.LogData) bool {
	sub_scope := scope.Copy().AppendVars(log)
	defer sub_scope.Close()

	res := vql_filter.Query.Where.Reduce(ctx, sub_scope)
	return scope.Bool(res)
}

func FatalIfError(command *kingpin.CmdClause, cb func() error) {
	err := cb()
	kingpin.FatalIfError(err, "%s", command.FullCommand())
}

func init() {
	command_handlers = append(command_handlers, func(command string) bool {
		switch command {
		case parse_command.FullCommand():
			FatalIfError(parse_command, doParse)
		default:
			return false
		}
		return true
	})
}
