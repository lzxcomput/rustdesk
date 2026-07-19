package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
)

func main() {
	directory := flag.String("dir", defaultAuditDirectory(), "RustDesk audit JSONL directory")
	checkpoint := flag.String("checkpoint", "", "checkpoint file (default: <dir>/.consumer-checkpoint.json)")
	interval := flag.Duration("interval", time.Second, "directory rescan interval")
	once := flag.Bool("once", false, "scan available records once and exit")
	flag.Parse()

	if *checkpoint == "" {
		*checkpoint = filepath.Join(*directory, ".consumer-checkpoint.json")
	}
	consumer, err := NewConsumer(*directory, *checkpoint, &JSONLineHandler{Writer: os.Stdout})
	if err != nil {
		fatal(err)
	}
	if *once {
		if err := consumer.Scan(); err != nil {
			fatal(err)
		}
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := consumer.Run(ctx, *interval); err != nil {
		fatal(err)
	}
}

func defaultAuditDirectory() string {
	if runtime.GOOS == "windows" {
		if programData := os.Getenv("ProgramData"); programData != "" {
			return filepath.Join(programData, "RustDesk", "audit")
		}
		return `C:\ProgramData\RustDesk\audit`
	}
	return "/var/log/rustdesk/audit"
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "rustdesk-audit-consumer:", err)
	os.Exit(1)
}
