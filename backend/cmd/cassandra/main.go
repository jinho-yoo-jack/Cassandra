package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/jinho-yoo-jack/Cassandra/backend/cmd/cassandra/app"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := app.Execute(ctx, os.Args[1:], os.Stdout, os.Stderr)
	cancel()
	os.Exit(code)
}
