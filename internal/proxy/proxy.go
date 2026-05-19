// Package proxy маршрутизирует JSON-RPC сообщения между локальным транспортом
// (stdio) и удалённым MCP-сервером (Streamable HTTP).
//
// Интерфейсы Transport и Remote, а также тип MessageOrError и sentinel
// ErrSessionLost определены здесь — это consumer-side контракты, к которым
// прицепляются реализации в пакетах stdio и httpmcp.
package proxy

import (
	"context"
	"errors"
	"log/slog"

	"github.com/dezer32/mcp-remote/internal/jsonrpc"
)

// ErrSessionLost — sentinel, сигнализирующий что remote вернул 404 на запрос
// с Mcp-Session-Id (сессия истекла). НЕ должен попадать в исходящие JSON-RPC
// сообщения клиенту — proxy перехватывает его и запускает recovery.
var ErrSessionLost = errors.New("mcp session lost (404 Mcp-Session-Id)")

// MessageOrError — единица канала из Remote.Send/Listen. Если Err == nil,
// валиден Msg; иначе валидна Err (включая ErrSessionLost).
type MessageOrError struct {
	Msg jsonrpc.Message
	Err error
}

// Transport — локальный stdio-канал к MCP-клиенту (Claude Desktop и т.п.).
type Transport interface {
	// Read блокируется до прихода сообщения. На EOF → io.EOF.
	// На отмену ctx → ctx.Err() (фоновая read-горутина может остаться висеть до закрытия stdin).
	Read(ctx context.Context) (jsonrpc.Message, error)
	// Write атомарно записывает все msgs в порядке аргументов под единым мьютексом.
	Write(ctx context.Context, msgs ...jsonrpc.Message) error
	Close() error
}

// Remote — удалённый MCP-сервер по Streamable HTTP transport.
type Remote interface {
	// Send: для notification/response → закрытый канал сразу после 202.
	// Для request → канал получает финальный response и server-initiated
	// request/notification, привязанные к этому request-у; закрывается после
	// окончания SSE-стрима. На session loss → MessageOrError{Err: ErrSessionLost}
	// и закрытие канала.
	Send(ctx context.Context, msg jsonrpc.Message) (<-chan MessageOrError, error)
	// Listen — GET SSE для server-initiated вне client-request. Контракт ошибок
	// тот же, что у Send.
	Listen(ctx context.Context) (<-chan MessageOrError, error)
	// SetProtocolVersion вызывается proxy один раз после успешного initialize.
	SetProtocolVersion(version string)
	// ResetSession очищает кэшированный Mcp-Session-Id (используется recovery).
	ResetSession()
	// Close посылает DELETE на endpoint и освобождает ресурсы.
	Close(ctx context.Context) error
}

// Proxy — точка соединения Transport ↔ Remote. Конструируется в main.go.
type Proxy struct {
	transport Transport
	remote    Remote
	log       *slog.Logger
}

// New собирает proxy. Логика — в Run.
func New(t Transport, r Remote, log *slog.Logger) *Proxy {
	return &Proxy{transport: t, remote: r, log: log}
}

// Run — главный цикл. Реализация — unit 5.
func (p *Proxy) Run(ctx context.Context) error {
	return errors.New("proxy.Run: not implemented")
}
