package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	kingpin "github.com/alecthomas/kingpin/v2"
)

type CommandHandler func(command string) bool

var (
	app = kingpin.New("unifiedlog_parser",
		"A tool for parsing unified logs.")

	verbose_flag = app.Flag(
		"verbose", "Show verbose information").
		Short('v').Bool()

	command_handlers []CommandHandler
)

func Install_sig_handler() (context.Context, context.CancelFunc) {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		select {
		case <-quit:
			// Ordered shutdown now.
			cancel()

		case <-ctx.Done():
			return
		}
	}()

	return ctx, cancel
}

func main() {
	app.HelpFlag.Short('h')
	app.UsageTemplate(kingpin.CompactUsageTemplate)
	command := kingpin.MustParse(app.Parse(os.Args[1:]))

	if *verbose_flag {
	}

	for _, command_handler := range command_handlers {
		if command_handler(command) {
			break
		}
	}
}
