// Package oauth реализует OAuth 2.1 для MCP: PKCE + RFC 7591 Dynamic Client
// Registration + двойной discovery (RFC 9728 PRM либо RFC 8414 fallback).
//
// Provider реализует contract httpmcp.TokenProvider.
package oauth

import (
	"context"
	"errors"
	"log/slog"

	"github.com/dezer32/mcp-remote/internal/config"
)

// Opener абстрагирует открытие URL в браузере (для тестов).
type Opener interface {
	Open(ctx context.Context, url string) error
}

// Provider — OAuth-провайдер. Реализация — unit 4.
type Provider struct {
	cfg    *config.Config
	opener Opener
	log    *slog.Logger
}

// New создаёт Provider.
func New(cfg *config.Config, opener Opener, log *slog.Logger) *Provider {
	return &Provider{cfg: cfg, opener: opener, log: log}
}

// Token возвращает текущий access-токен (с авто-refresh при истечении).
// "" → auth не нужен / Authorization прокидывается пользователем.
func (p *Provider) Token(ctx context.Context) (string, error) {
	return "", errors.New("oauth.Provider.Token: not implemented")
}

// HandleUnauthorized обрабатывает 401: парсит challenge, делает refresh либо
// полный authorize, после чего токен будет доступен через Token.
func (p *Provider) HandleUnauthorized(ctx context.Context, wwwAuthenticate string) error {
	return errors.New("oauth.Provider.HandleUnauthorized: not implemented")
}
