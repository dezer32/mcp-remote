// Command mcp-remote — stdio↔Streamable HTTP MCP-прокси.
// См. README.md и план реализации.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/dezer32/mcp-remote/internal/config"
	"github.com/dezer32/mcp-remote/internal/httpmcp"
	"github.com/dezer32/mcp-remote/internal/logging"
	"github.com/dezer32/mcp-remote/internal/oauth"
	"github.com/dezer32/mcp-remote/internal/proxy"
	"github.com/dezer32/mcp-remote/internal/stdio"
)

// Compile-time проверки consumer-side контрактов. Если worker сломает сигнатуру
// в своём пакете — здесь будет ошибка сборки.
var (
	_ proxy.Transport       = (*stdio.Transport)(nil)
	_ proxy.Remote          = (*httpmcp.Client)(nil)
	_ httpmcp.TokenProvider = (*oauth.Provider)(nil)
	_ oauth.Opener          = oauth.DefaultOpener{}
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "mcp-remote: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Parse(os.Args[1:])
	if err != nil {
		return fmt.Errorf("parse config: %w", err)
	}

	log := logging.New(cfg.Debug, cfg.Silent)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	oauthProvider := oauth.New(cfg, oauth.DefaultOpener{}, log)

	httpClient, err := httpmcp.New(cfg, oauthProvider, log)
	if err != nil {
		return fmt.Errorf("new http client: %w", err)
	}

	stdioTransport := stdio.New(os.Stdin, os.Stdout, log)

	p := proxy.New(stdioTransport, httpClient, log)

	log.Info("mcp-remote starting", slog.String("server", cfg.ServerURL))
	return p.Run(ctx)
}
