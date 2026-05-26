package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/lvbu1984/qave-recovery-cli/internal/launcher"
)

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Qave Recovery Tool could not start: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var rootFlag string
	var noBrowser bool
	var idleTimeout time.Duration
	flag.StringVar(&rootFlag, "root", "", "static recovery tool directory for development smoke tests")
	flag.BoolVar(&noBrowser, "no-browser", false, "start the localhost server without opening a browser")
	flag.DurationVar(&idleTimeout, "idle-timeout", 6*time.Hour, "automatic shutdown after no local page requests")
	flag.Parse()

	root, err := launcher.ResolveStaticRoot(rootFlag, "")
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	server, err := launcher.Start(ctx, launcher.Config{
		Root:        root,
		OpenBrowser: !noBrowser,
		IdleTimeout: idleTimeout,
		Stdout:      os.Stdout,
	})
	if err != nil {
		return err
	}

	return server.Wait()
}
