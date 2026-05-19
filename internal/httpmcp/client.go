// Package httpmcp реализует Remote (см. internal/proxy) поверх MCP
// Streamable HTTP transport (спецификация 2025-03-26).
//
// Сюда же вынесен consumer-side контракт TokenProvider — абстракция получения
// токена и обработки 401, которую реализует пакет oauth.
package httpmcp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"

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

// Internal constants.
const (
	headerSessionID       = "Mcp-Session-Id"
	headerProtocolVersion = "MCP-Protocol-Version"
	headerLastEventID     = "Last-Event-ID"

	contentTypeJSON = "application/json"
	contentTypeSSE  = "text/event-stream"

	maxErrorBody        = 1024
	responseHeaderTout  = 30 * time.Second
	listenBackoffMin    = 1 * time.Second
	listenBackoffMax    = 30 * time.Second
	closeRequestTimeout = 2 * time.Second
)

// Client — Streamable HTTP клиент. Реализует proxy.Remote.
type Client struct {
	cfg *config.Config
	tp  TokenProvider
	log *slog.Logger

	httpOnce sync.Once
	httpC    *http.Client

	session sessionState
}

// New создаёт клиент. Возвращает ошибку если cfg не валиден на этом уровне
// (например, ServerURL пустой).
func New(cfg *config.Config, tp TokenProvider, log *slog.Logger) (*Client, error) {
	if cfg == nil {
		return nil, errors.New("httpmcp: nil config")
	}
	if log == nil {
		log = slog.Default()
	}
	return &Client{cfg: cfg, tp: tp, log: log}, nil
}

// httpClient lazy-init под sync.Once. Один shared экземпляр на Client.
func (c *Client) httpClient() *http.Client {
	c.httpOnce.Do(func() {
		c.httpC = &http.Client{
			Transport: &http.Transport{
				ResponseHeaderTimeout: responseHeaderTout,
			},
			CheckRedirect: checkRedirect,
		}
	})
	return c.httpC
}

// setRequestHeaders проставляет user-defined cfg.Headers, Accept, MCP-Session-Id,
// MCP-Protocol-Version и Authorization из tp.Token если user не задал свой.
// Заголовки из cfg.Headers ставятся ДО системных — поэтому пользовательский
// Authorization перебьёт OAuth, а Accept останется системным.
func (c *Client) setRequestHeaders(ctx context.Context, req *http.Request, withContentType bool) error {
	for _, h := range c.cfg.Headers {
		req.Header.Set(h.Name, h.Value)
	}

	req.Header.Set("Accept", contentTypeJSON+", "+contentTypeSSE)
	if withContentType {
		req.Header.Set("Content-Type", contentTypeJSON)
	}

	if sid := c.session.getSessionID(); sid != "" {
		req.Header.Set(headerSessionID, sid)
	}
	if pv := c.session.getProtocolVersion(); pv != "" {
		req.Header.Set(headerProtocolVersion, pv)
	}

	if req.Header.Get("Authorization") == "" && c.tp != nil {
		t, err := c.tp.Token(ctx)
		if err != nil {
			return fmt.Errorf("token provider: %w", err)
		}
		if t != "" {
			req.Header.Set("Authorization", "Bearer "+t)
		}
	}
	return nil
}

// extractSessionID читает Mcp-Session-Id из ответа и сохраняет, если валиден.
func (c *Client) extractSessionID(resp *http.Response) {
	id := resp.Header.Get(headerSessionID)
	if id == "" {
		return
	}
	if !isASCIIPrintable(id) {
		c.log.Warn("ignored non-ASCII-printable Mcp-Session-Id", slog.String("value", id))
		return
	}
	c.session.setSessionID(id)
}

// Send — POST одного JSON-RPC сообщения. См. интерфейс proxy.Remote.
func (c *Client) Send(ctx context.Context, msg jsonrpc.Message) (<-chan proxy.MessageOrError, error) {
	body, err := jsonrpc.Encode(msg)
	if err != nil {
		return nil, fmt.Errorf("encode: %w", err)
	}
	out := make(chan proxy.MessageOrError, 4)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				c.emitErr(ctx, out, fmt.Errorf("httpmcp.Send panic: %v", r))
			}
			close(out)
		}()
		c.sendOnce(ctx, body, out, false)
	}()
	return out, nil
}

// sendOnce выполняет один POST и обрабатывает ответ. На 401 — рекурсивно
// вызывает себя с retried=true (это даёт ровно один retry).
// НЕ закрывает out — caller отвечает за close.
func (c *Client) sendOnce(ctx context.Context, body []byte, out chan<- proxy.MessageOrError, retried bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.ServerURL, bytes.NewReader(body))
	if err != nil {
		c.emitErr(ctx, out, fmt.Errorf("new request: %w", err))
		return
	}
	if err = c.setRequestHeaders(ctx, req, true); err != nil {
		c.emitErr(ctx, out, err)
		return
	}

	resp, err := c.httpClient().Do(req)
	if err != nil {
		c.emitErr(ctx, out, fmt.Errorf("http do: %w", err))
		return
	}

	switch resp.StatusCode {
	case http.StatusAccepted:
		c.extractSessionID(resp)
		drainAndClose(resp.Body)
		return

	case http.StatusOK:
		c.extractSessionID(resp)
		c.handleOK(ctx, resp, out)
		return

	case http.StatusUnauthorized:
		if !c.handle401(ctx, resp, retried, out) {
			return
		}
		c.sendOnce(ctx, body, out, true)
		return

	case http.StatusNotFound:
		c.emit404(ctx, resp, out)
		return

	default:
		excerpt := readBodyExcerpt(resp.Body)
		resp.Body.Close()
		c.emitErr(ctx, out, fmt.Errorf("http %d: %s", resp.StatusCode, excerpt))
	}
}

// handleOK разбирает тело 200 OK по Content-Type и emit-ит сообщения.
// Body закрывается внутри.
func (c *Client) handleOK(ctx context.Context, resp *http.Response, out chan<- proxy.MessageOrError) {
	ct := resp.Header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil {
		drainAndClose(resp.Body)
		c.emitErr(ctx, out, fmt.Errorf("parse content-type %q: %w", ct, err))
		return
	}
	defer resp.Body.Close()
	switch mediaType {
	case contentTypeJSON:
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			c.emitErr(ctx, out, fmt.Errorf("read body: %w", err))
			return
		}
		trimmed := bytes.TrimSpace(data)
		if len(trimmed) == 0 {
			return
		}
		msgs, err := jsonrpc.BatchDecode(trimmed)
		if err != nil {
			c.emitErr(ctx, out, fmt.Errorf("decode: %w", err))
			return
		}
		for _, m := range msgs {
			if !c.emit(ctx, out, proxy.MessageOrError{Msg: m}) {
				return
			}
		}
	case contentTypeSSE:
		if err := parseSSE(ctx, resp.Body, out, nil); err != nil && !errors.Is(err, context.Canceled) {
			c.emitErr(ctx, out, fmt.Errorf("sse: %w", err))
		}
	default:
		c.emitErr(ctx, out, fmt.Errorf("unexpected content-type: %s", ct))
	}
}

// Listen — GET SSE для server-initiated сообщений. См. proxy.Remote.
func (c *Client) Listen(ctx context.Context) (<-chan proxy.MessageOrError, error) {
	out := make(chan proxy.MessageOrError, 4)
	go c.doListen(ctx, out)
	return out, nil
}

// doListen — цикл reconnect для GET SSE.
func (c *Client) doListen(ctx context.Context, out chan<- proxy.MessageOrError) {
	defer close(out)

	var (
		lastEventID string
		backoff     time.Duration // 0 → первый retry без задержки
		retried401  bool
	)

	setLastID := func(id string) {
		lastEventID = id
	}

	for {
		if ctx.Err() != nil {
			return
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.ServerURL, nil)
		if err != nil {
			c.emitErr(ctx, out, fmt.Errorf("new request: %w", err))
			return
		}
		if err = c.setRequestHeaders(ctx, req, false); err != nil {
			c.emitErr(ctx, out, err)
			return
		}
		if lastEventID != "" {
			req.Header.Set(headerLastEventID, lastEventID)
		}

		resp, err := c.httpClient().Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			c.log.Debug("listen: request error, will reconnect", slog.String("err", err.Error()))
			if !c.sleepBackoff(ctx, &backoff) {
				return
			}
			continue
		}

		switch resp.StatusCode {
		case http.StatusMethodNotAllowed:
			// Сервер не поддерживает GET SSE — clean exit.
			drainAndClose(resp.Body)
			return

		case http.StatusUnauthorized:
			if !c.handle401(ctx, resp, retried401, out) {
				return
			}
			retried401 = true
			continue

		case http.StatusNotFound:
			c.emit404(ctx, resp, out)
			return

		case http.StatusOK:
			c.extractSessionID(resp)
			retried401 = false
			ct := resp.Header.Get("Content-Type")
			mediaType, _, mtErr := mime.ParseMediaType(ct)
			if mtErr != nil || mediaType != contentTypeSSE {
				drainAndClose(resp.Body)
				c.emitErr(ctx, out, fmt.Errorf("listen: unexpected content-type %q", ct))
				return
			}
			err := parseSSE(ctx, resp.Body, out, setLastID)
			resp.Body.Close()
			if ctx.Err() != nil {
				return
			}
			if err != nil && !errors.Is(err, io.EOF) {
				c.log.Debug("listen: sse error, will reconnect", slog.String("err", err.Error()))
			}
			// Сбрасываем backoff — connect был успешен.
			backoff = 0
			if !c.sleepBackoff(ctx, &backoff) {
				return
			}
			continue

		default:
			excerpt := readBodyExcerpt(resp.Body)
			resp.Body.Close()
			c.emitErr(ctx, out, fmt.Errorf("listen: http %d: %s", resp.StatusCode, excerpt))
			return
		}
	}
}

// sleepBackoff ждёт текущий backoff и увеличивает его (capped listenBackoffMax,
// с jitter). Если backoff == 0 — ничего не ждёт и сразу выставляет минимум.
// Возвращает false если ctx отменён.
func (c *Client) sleepBackoff(ctx context.Context, backoff *time.Duration) bool {
	if *backoff == 0 {
		*backoff = listenBackoffMin
		return ctx.Err() == nil
	}
	// jitter ±25%
	jitter := time.Duration(rand.Int63n(int64(*backoff / 2)))
	wait := *backoff - (*backoff / 4) + jitter
	select {
	case <-ctx.Done():
		return false
	case <-time.After(wait):
	}
	*backoff *= 2
	if *backoff > listenBackoffMax {
		*backoff = listenBackoffMax
	}
	return true
}

// SetProtocolVersion вызывается proxy после успешного initialize.
func (c *Client) SetProtocolVersion(version string) {
	c.session.setProtocolVersion(version)
}

// ResetSession обнуляет Mcp-Session-Id (использует proxy перед recovery).
func (c *Client) ResetSession() {
	c.session.clearSessionID()
}

// Close посылает DELETE на endpoint если у нас есть sessionID и завершает работу.
func (c *Client) Close(ctx context.Context) error {
	sid := c.session.getSessionID()
	if sid == "" {
		return nil
	}
	delCtx, cancel := context.WithTimeout(ctx, closeRequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(delCtx, http.MethodDelete, c.cfg.ServerURL, nil)
	if err != nil {
		c.log.Warn("close: new request", slog.String("err", err.Error()))
		return nil
	}
	if err = c.setRequestHeaders(delCtx, req, false); err != nil {
		c.log.Warn("close: set headers", slog.String("err", err.Error()))
		return nil
	}

	resp, err := c.httpClient().Do(req)
	if err != nil {
		c.log.Warn("close: do", slog.String("err", err.Error()))
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusMethodNotAllowed {
		// Сервер не поддерживает DELETE — ignore.
		return nil
	}
	if resp.StatusCode >= 400 {
		c.log.Warn("close: non-2xx", slog.Int("status", resp.StatusCode))
	}
	return nil
}

// handle401 — общая обработка 401: парс WWW-Authenticate, вызов tp.HandleUnauthorized,
// emit ошибки на провал. Закрывает resp.Body. Возвращает true если caller-у можно
// повторить запрос (один раз — retried контролирует), иначе false (ошибка уже emit-нута).
func (c *Client) handle401(ctx context.Context, resp *http.Response, retried bool, out chan<- proxy.MessageOrError) bool {
	www := resp.Header.Get("WWW-Authenticate")
	drainAndClose(resp.Body)
	if retried {
		c.emitErr(ctx, out, fmt.Errorf("http 401 after retry"))
		return false
	}
	if c.tp == nil {
		c.emitErr(ctx, out, fmt.Errorf("http 401: no token provider"))
		return false
	}
	if err := c.tp.HandleUnauthorized(ctx, www); err != nil {
		c.emitErr(ctx, out, fmt.Errorf("handle unauthorized: %w", err))
		return false
	}
	return true
}

// emit404 — общая обработка 404. ErrSessionLost если у нас есть session id,
// иначе обычный http-error. Закрывает resp.Body (симметрично handle401).
func (c *Client) emit404(ctx context.Context, resp *http.Response, out chan<- proxy.MessageOrError) {
	drainAndClose(resp.Body)
	if c.session.getSessionID() != "" {
		c.emitErr(ctx, out, proxy.ErrSessionLost)
		return
	}
	c.emitErr(ctx, out, fmt.Errorf("http 404"))
}

// emit неблокирующе отправляет moe в out, либо завершается на ctx cancel.
// Возвращает false если ctx отменён.
func (c *Client) emit(ctx context.Context, out chan<- proxy.MessageOrError, moe proxy.MessageOrError) bool {
	select {
	case <-ctx.Done():
		return false
	case out <- moe:
		return true
	}
}

// emitErr вспомогательно отправляет ошибку.
func (c *Client) emitErr(ctx context.Context, out chan<- proxy.MessageOrError, err error) {
	c.emit(ctx, out, proxy.MessageOrError{Err: err})
}

// drainAndClose закрывает body, читая остаток (для keep-alive).
func drainAndClose(body io.ReadCloser) {
	_, _ = io.Copy(io.Discard, io.LimitReader(body, 1<<20))
	body.Close()
}

// readBodyExcerpt читает до maxErrorBody байт для error-сообщения.
func readBodyExcerpt(body io.Reader) string {
	buf, _ := io.ReadAll(io.LimitReader(body, maxErrorBody))
	s := strings.TrimSpace(string(buf))
	if s == "" {
		return "<empty body>"
	}
	return s
}
