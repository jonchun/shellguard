// Command shellguard runs the MCP server as a stdio subprocess.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/jonchun/shellguard"
)

var version = "dev"

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{}))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, logger, os.Args[1:]); err != nil {
		logger.Error("shellguard failed", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, logger *slog.Logger, args []string) error {
	if len(args) == 0 {
		return runStdio(ctx, logger)
	}

	switch args[0] {
	case "help", "-h", "--help":
		printHelp(os.Stdout)
		return nil
	case "version", "-v", "--version":
		fmt.Printf("shellguard %s\n", version)
		return nil
	default:
		printHelp(os.Stderr)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runStdio(ctx context.Context, logger *slog.Logger) error {
	err := shellguard.RunStdio(ctx, shellguard.Config{Logger: logger})
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func printHelp(w io.Writer) {
	_, _ = fmt.Fprintln(w, "shellguard - security-first MCP server for remote command execution")
	_, _ = fmt.Fprintln(w, "")
	_, _ = fmt.Fprintln(w, "Usage:")
	_, _ = fmt.Fprintln(w, "  shellguard          Start MCP server over stdio (default)")
	_, _ = fmt.Fprintln(w, "  shellguard help      Show this help")
	_, _ = fmt.Fprintln(w, "  shellguard version   Show version")
}
