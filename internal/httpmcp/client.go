// Package httpmcp реализует Remote (см. internal/proxy) поверх MCP
// Streamable HTTP transport (спецификация 2025-03-26).
//
// Сюда же вынесен consumer-side контракт TokenProvider — абстракция получения
// токена и обработки 401, которую реализует пакет oauth.
package httpmcp

import (
	"context"
	"errors"
	"log/slog"

	"github.com/dezer32/mcp-remote/internal/config"
	"github.com/dezer32/mcp-remote/internal/jsonrpc"
	"github.com/dezer32/mcp-remote/internal/proxy"
)

// TokenProvider абстрагирует получение Authorization для каждого запроса.
// Если конфиг содержит явный заголовок Authorization от пользователя —
// провайдер может возвращать "" (заголовок поставит сам httpmcp.Client из cfg).
type TokenProvider interface {
	// Token возвращает текущий access-токен. "" → заголовок не ставится.
	Token(ctx context.Context) (string, error)
	// HandleUnauthorized вызывается на HTTP 401. wwwAuthenticate — точное
	// значение заголовка WWW-Authenticate из ответа (может быть пустым).
	// На успех (новый токен/новая сессия) httpmcp выполнит однократный retry.
	HandleUnauthorized(ctx context.Context, wwwAuthenticate string) error
}

// Client — Streamable HTTP клиент. Реализация — unit 3.
type Client struct {
	cfg *config.Config
	tp  TokenProvider
	log *slog.Logger
}

// New создаёт клиент. Возвращает ошибку если cfg не валиден на этом уровне
// (например, ServerURL пустой).
func New(cfg *config.Config, tp TokenProvider, log *slog.Logger) (*Client, error) {
	return &Client{cfg: cfg, tp: tp, log: log}, nil
}

// Send — POST одного JSON-RPC сообщения. См. интерфейс proxy.Remote.
func (c *Client) Send(ctx context.Context, msg jsonrpc.Message) (<-chan proxy.MessageOrError, error) {
	return nil, errors.New("httpmcp.Client.Send: not implemented")
}

// Listen — GET SSE для server-initiated сообщений. См. proxy.Remote.
func (c *Client) Listen(ctx context.Context) (<-chan proxy.MessageOrError, error) {
	return nil, errors.New("httpmcp.Client.Listen: not implemented")
}

// SetProtocolVersion вызывается proxy после успешного initialize.
func (c *Client) SetProtocolVersion(version string) {}

// ResetSession обнуляет Mcp-Session-Id (использует proxy перед recovery).
func (c *Client) ResetSession() {}

// Close посылает DELETE на endpoint и завершает работу.
func (c *Client) Close(ctx context.Context) error {
	return nil
}
